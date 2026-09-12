from __future__ import annotations
from collections import Counter
from datetime import datetime
import hmac
from urllib.parse import quote, urlparse
import httpx
from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.orm import Session
from starlette.middleware.sessions import SessionMiddleware
from .asset_intelligence import compare_findings, surface_summary, technology_inventory
from .config import VERSION, ADMIN_PASSWORD, SESSION_SECRET, ALLOW_PRIVATE_TEST_TARGETS
from .db import Base, SessionLocal, db_session, engine
from .models import AuditLog, ScanRequest, Target, User
from .quality_intelligence import assessment_quality, remediation_queue
from .risk_engine import risk_summary
from .sarif_export import build_sarif
from .scanner import safe_scan
from .security import hash_password, is_public_host, normalize_target, verify_password

Base.metadata.create_all(engine)
app=FastAPI(title="NEXVARY VScan",version=VERSION)
app.add_middleware(SessionMiddleware,secret_key=SESSION_SECRET,https_only=False,same_site="lax")
app.mount("/static",StaticFiles(directory="app/static"),name="static")
templates=Jinja2Templates(directory="app/templates")

def ensure_admin():
    db=SessionLocal()
    try:
        if not db.scalar(select(User).where(User.username=="admin")):
            db.add(User(username="admin",password_hash=hash_password(ADMIN_PASSWORD),role="admin")); db.commit()
    finally: db.close()
ensure_admin()

def current_user(request:Request,db:Session=Depends(db_session)):
    uid=request.session.get("user_id"); user=db.get(User,uid) if uid else None
    if not user or not user.active: raise HTTPException(401,"Authentication required")
    return user

def require_admin(user:User=Depends(current_user)):
    if user.role!="admin": raise HTTPException(403,"NEXVARY admin access required")
    return user

def audit(db,actor,action,detail=""): db.add(AuditLog(actor=actor,action=action,detail=detail))

def _previous_completed_scan(db:Session,scan:ScanRequest):
    return db.scalar(select(ScanRequest).where(ScanRequest.target_id==scan.target_id,ScanRequest.status=="completed",ScanRequest.id<scan.id).order_by(ScanRequest.id.desc()).limit(1))

def _assessment_context(db:Session,scan:ScanRequest)->dict:
    order={"Critical":0,"High":1,"Medium":2,"Low":3,"Info":4}
    findings=sorted(scan.findings,key=lambda f:(order.get(f.severity,9),f.title,f.endpoint or ""))
    surfaces=sorted(scan.surface_items,key=lambda s:(s.category,s.value))
    previous=_previous_completed_scan(db,scan)
    trend=compare_findings(findings,previous.findings) if previous else {"new":[],"resolved":[],"persistent":[],"new_count":0,"resolved_count":0,"persistent_count":0}
    return {
        "findings":findings,"surfaces":surfaces,
        "surface_counts":Counter(s.category for s in surfaces),
        "severity_counts":Counter(f.severity for f in findings),
        "confirmed_count":sum(1 for f in findings if f.confirmed),
        "potential_count":sum(1 for f in findings if not f.confirmed),
        "risk":risk_summary(findings),
        "asset_intelligence":surface_summary(surfaces),
        "technology_inventory":technology_inventory(surfaces),
        "trend":trend,"previous_scan":previous,
        "quality":assessment_quality(scan,findings,surfaces),
        "remediation_queue":remediation_queue(findings),
    }

@app.exception_handler(HTTPException)
async def http_error(request:Request,exc:HTTPException):
    if exc.status_code==401 and request.url.path not in {"/login","/health"}: return RedirectResponse("/login",303)
    return JSONResponse({"detail":exc.detail},status_code=exc.status_code)

@app.get("/login",response_class=HTMLResponse)
def login_page(request:Request):
    if request.session.get("user_id"): return RedirectResponse("/",303)
    return templates.TemplateResponse("login.html",{"request":request,"error":None,"version":VERSION})

@app.post("/login")
def login(request:Request,username:str=Form(...),password:str=Form(...),db:Session=Depends(db_session)):
    user=db.scalar(select(User).where(User.username==username.strip()))
    if not user or not verify_password(password,user.password_hash): return templates.TemplateResponse("login.html",{"request":request,"error":"Invalid username or password","version":VERSION},status_code=401)
    request.session["user_id"]=user.id; audit(db,user.username,"login"); db.commit(); return RedirectResponse("/",303)

@app.post("/logout")
def logout(request:Request): request.session.clear(); return RedirectResponse("/login",303)

@app.get("/",response_class=HTMLResponse)
def dashboard(request:Request,db:Session=Depends(db_session),user:User=Depends(current_user)):
    targets=db.scalars(select(Target).order_by(Target.created_at.desc())).all(); scans=db.scalars(select(ScanRequest).order_by(ScanRequest.created_at.desc())).all(); counts={k:0 for k in ["pending","approved","running","completed","rejected"]}
    for s in scans: counts[s.status]=counts.get(s.status,0)+1
    return templates.TemplateResponse("dashboard.html",{"request":request,"targets":targets,"scans":scans,"counts":counts,"user":user,"version":VERSION,"notice":request.query_params.get("notice"),"error":request.query_params.get("error")})

@app.post("/targets")
def create_target(name:str=Form(...),url:str=Form(...),owner:str=Form(...),db:Session=Depends(db_session),user:User=Depends(current_user)):
    try: normalized=normalize_target(url)
    except ValueError as exc: raise HTTPException(400,str(exc))
    target=Target(name=name.strip(),url=normalized,owner=owner.strip()); db.add(target); audit(db,user.username,"target.created",normalized); db.commit(); return RedirectResponse("/",303)

@app.post("/targets/{target_id}/verify")
def verify_target(target_id:int,db:Session=Depends(db_session),user:User=Depends(current_user)):
    target=db.get(Target,target_id)
    if not target: raise HTTPException(404,"Target not found")
    verification_url=target.url+"/.well-known/nexvary-verification.txt"; host=urlparse(target.url).hostname or ""
    if not (ALLOW_PRIVATE_TEST_TARGETS or is_public_host(host)): return RedirectResponse(f"/?error={quote('Verification host is not publicly routable.')}",303)
    ok=False
    try:
        with httpx.Client(timeout=8,follow_redirects=False,headers={"User-Agent":f"NEXVARY-VScan/{VERSION} Ownership-Verification"}) as client: r=client.get(verification_url)
        ok=r.status_code==200 and hmac.compare_digest(r.text.strip(),target.verification_token)
    except Exception: pass
    if not ok: return RedirectResponse(f"/?error={quote('Ownership verification failed. Publish the exact token at '+verification_url+' and try again.')}",303)
    target.verified=True; target.verified_at=datetime.utcnow(); audit(db,user.username,"target.verified",target.url); db.commit(); return RedirectResponse(f"/?notice={quote('Ownership verified successfully. You can now request a NEXVARY-approved scan.')}",303)

@app.post("/targets/{target_id}/request-scan")
def request_scan(target_id:int,db:Session=Depends(db_session),user:User=Depends(current_user)):
    target=db.get(Target,target_id)
    if not target: raise HTTPException(404,"Target not found")
    if not target.verified: raise HTTPException(403,"Target ownership must be verified before scan request")
    db.add(ScanRequest(target_id=target_id,requested_by=user.username,status="pending")); audit(db,user.username,"scan.requested",target.url); db.commit(); return RedirectResponse("/admin",303)

@app.get("/admin",response_class=HTMLResponse)
def admin(request:Request,db:Session=Depends(db_session),user:User=Depends(require_admin)):
    scans=db.scalars(select(ScanRequest).order_by(ScanRequest.created_at.desc())).all(); logs=db.scalars(select(AuditLog).order_by(AuditLog.created_at.desc()).limit(40)).all(); return templates.TemplateResponse("admin.html",{"request":request,"scans":scans,"logs":logs,"user":user,"version":VERSION})

@app.post("/admin/scans/{scan_id}/approve")
def approve(scan_id:int,note:str=Form(""),db:Session=Depends(db_session),user:User=Depends(require_admin)):
    scan=db.get(ScanRequest,scan_id)
    if not scan or scan.status!="pending": raise HTTPException(409,"Only pending requests can be approved")
    if not scan.target.verified: raise HTTPException(403,"Target verification required")
    scan.status="approved"; scan.approved_by=user.username; scan.approval_note=note.strip(); scan.approved_at=datetime.utcnow(); audit(db,user.username,"scan.approved",f"scan #{scan.id}"); db.commit(); return RedirectResponse("/admin",303)

@app.post("/admin/scans/{scan_id}/reject")
def reject(scan_id:int,note:str=Form(""),db:Session=Depends(db_session),user:User=Depends(require_admin)):
    scan=db.get(ScanRequest,scan_id)
    if not scan or scan.status!="pending": raise HTTPException(409,"Only pending requests can be rejected")
    scan.status="rejected"; scan.approved_by=user.username; scan.approval_note=note.strip(); scan.approved_at=datetime.utcnow(); audit(db,user.username,"scan.rejected",f"scan #{scan.id}"); db.commit(); return RedirectResponse("/admin",303)

@app.post("/admin/scans/{scan_id}/run")
def run(scan_id:int,db:Session=Depends(db_session),user:User=Depends(require_admin)):
    scan=db.get(ScanRequest,scan_id)
    if not scan or scan.status!="approved" or not scan.approved_by: raise HTTPException(403,"NEXVARY team approval is required before scanning")
    if not scan.target.verified: raise HTTPException(403,"Verified ownership is required")
    audit(db,user.username,"scan.started",f"scan #{scan.id}"); db.commit(); safe_scan(db,scan); return RedirectResponse(f"/scans/{scan.id}",303)

@app.get("/scans/{scan_id}",response_class=HTMLResponse)
def scan_detail(scan_id:int,request:Request,db:Session=Depends(db_session),user:User=Depends(current_user)):
    scan=db.get(ScanRequest,scan_id)
    if not scan: raise HTTPException(404,"Scan not found")
    context=_assessment_context(db,scan); context.update({"request":request,"scan":scan,"user":user,"version":VERSION})
    return templates.TemplateResponse("scan.html",context)

@app.get("/scans/{scan_id}/report",response_class=HTMLResponse)
def report(scan_id:int,request:Request,db:Session=Depends(db_session),user:User=Depends(current_user)):
    scan=db.get(ScanRequest,scan_id)
    if not scan: raise HTTPException(404,"Scan not found")
    context=_assessment_context(db,scan); context.update({"request":request,"scan":scan,"user":user,"version":VERSION})
    return templates.TemplateResponse("report.html",context)

@app.get("/scans/{scan_id}/export.json")
def export(scan_id:int,db:Session=Depends(db_session),user:User=Depends(current_user)):
    scan=db.get(ScanRequest,scan_id)
    if not scan: raise HTTPException(404,"Scan not found")
    context=_assessment_context(db,scan); previous=context["previous_scan"]
    payload={"product":"NEXVARY VScan","version":VERSION,"stage":1500,"mode":"authorized-defensive","scan_id":scan.id,"status":scan.status,"target":{"name":scan.target.name,"url":scan.target.url,"owner":scan.target.owner,"verified":scan.target.verified},"approval":{"requested_by":scan.requested_by,"approved_by":scan.approved_by,"note":scan.approval_note},"metrics":{"security_score":scan.security_score,"pages_crawled":scan.pages_crawled,"requests_made":scan.requests_made,"duration_ms":scan.duration_ms},"risk_intelligence":context["risk"],"quality_intelligence":context["quality"],"remediation_queue":context["remediation_queue"],"asset_intelligence":context["asset_intelligence"],"technology_inventory":context["technology_inventory"],"trend":{"baseline_scan_id":previous.id if previous else None,"baseline_score":previous.security_score if previous else None,**context["trend"]},"findings":[{"severity":f.severity,"title":f.title,"category":f.category,"confidence":f.confidence,"confirmed":f.confirmed,"endpoint":f.endpoint,"detail":f.detail,"evidence":f.evidence,"remediation":f.remediation,"cwe":f.cwe,"owasp":f.owasp} for f in context["findings"]],"attack_surface":[{"category":i.category,"value":i.value,"source":i.source_endpoint,"method":i.method,"detail":i.detail} for i in context["surfaces"]]}
    return JSONResponse(payload,headers={"Content-Disposition":f'attachment; filename="nexvary-vscan-{scan.id}.json"'})

@app.get("/scans/{scan_id}/export.sarif")
def export_sarif(scan_id:int,db:Session=Depends(db_session),user:User=Depends(current_user)):
    scan=db.get(ScanRequest,scan_id)
    if not scan: raise HTTPException(404,"Scan not found")
    payload=build_sarif(scan,scan.findings,VERSION)
    return JSONResponse(payload,media_type="application/sarif+json",headers={"Content-Disposition":f'attachment; filename="nexvary-vscan-{scan.id}.sarif"'})

@app.get("/health")
def health(): return {"status":"ok","version":VERSION,"stage":1500,"mode":"authorized-defensive"}
