from __future__ import annotations
import re, time
from collections import deque
from datetime import datetime
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urldefrag, urljoin, urlparse
import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session
from .config import MAX_PAGES, MAX_REQUESTS, REQUEST_DELAY
from .models import Finding, ScanRequest, SurfaceItem
from .security import same_scope

STATIC_EXTENSIONS = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".css", ".woff", ".woff2", ".pdf", ".zip", ".mp4", ".mp3")

class SurfaceParser(HTMLParser):
    def __init__(self, base_url: str):
        super().__init__(convert_charrefs=True)
        self.base_url=base_url; self.links=[]; self.scripts=[]; self.forms=[]; self._form=None
    def handle_starttag(self, tag, attrs):
        d={str(k).lower():(v or "") for k,v in attrs}; tag=tag.lower()
        if tag=="a" and d.get("href"): self.links.append(urljoin(self.base_url,d["href"]))
        elif tag=="script" and d.get("src"): self.scripts.append(urljoin(self.base_url,d["src"]))
        elif tag=="form":
            self._form={"action":urljoin(self.base_url,d.get("action") or self.base_url),"method":(d.get("method") or "GET").upper(),"inputs":[]}
        elif tag in {"input","select","textarea"} and self._form is not None and d.get("name"):
            self._form["inputs"].append({"name":d["name"],"type":d.get("type",tag)})
    def handle_endtag(self, tag):
        if tag.lower()=="form" and self._form is not None:
            self.forms.append(self._form); self._form=None

def _add_finding(db:Session, scan:ScanRequest, severity,title,detail,remediation,endpoint,confirmed=True,category="Web Security",evidence="",cwe=None,owasp=None,status_code=None):
    exists=db.scalar(select(Finding).where(Finding.scan_request_id==scan.id, Finding.title==title, Finding.endpoint==endpoint))
    if not exists:
        db.add(Finding(scan_request_id=scan.id,severity=severity,title=title,detail=detail,remediation=remediation,endpoint=endpoint,confirmed=confirmed,confidence="High" if confirmed else "Low",category=category,evidence=evidence,cwe=cwe,owasp=owasp,status_code=status_code))

def _add_surface(db:Session, scan:ScanRequest, category,value,source=None,method=None,detail=""):
    exists=db.scalar(select(SurfaceItem).where(SurfaceItem.scan_request_id==scan.id, SurfaceItem.category==category, SurfaceItem.value==value[:900], SurfaceItem.source_endpoint==(source[:900] if source else None)))
    if not exists: db.add(SurfaceItem(scan_request_id=scan.id,category=category,value=value[:900],source_endpoint=source[:900] if source else None,method=method,detail=detail[:4000]))

def _analyze_response(db:Session, scan:ScanRequest, url:str, response:httpx.Response, body:str):
    headers={k.lower():v for k,v in response.headers.items()}
    checks=[("content-security-policy","Medium","Content-Security-Policy header missing","Add a restrictive CSP tailored to the application.","CWE-693"),("strict-transport-security","Medium","HSTS header missing","Enable HSTS after confirming HTTPS-only operation.","CWE-319"),("x-content-type-options","Low","X-Content-Type-Options header missing","Set X-Content-Type-Options: nosniff.","CWE-693"),("referrer-policy","Low","Referrer-Policy header missing","Set a suitable Referrer-Policy.","CWE-200")]
    for key,sev,title,rem,cwe in checks:
        if key not in headers: _add_finding(db,scan,sev,title,f"The response did not include {key}.",rem,url,category="HTTP Security",evidence=f"HTTP {response.status_code}",cwe=cwe,status_code=response.status_code)
    if headers.get("access-control-allow-origin")=="*": _add_finding(db,scan,"Low","Wildcard CORS policy observed","The response allows any origin.","Restrict allowed origins to trusted application origins where cross-origin access is required.",url,category="CORS",evidence="Access-Control-Allow-Origin: *",cwe="CWE-942",status_code=response.status_code)
    server=headers.get("server")
    if server: _add_surface(db,scan,"technology",server,url,detail="Server header")
    for cookie in response.headers.get_list("set-cookie"):
        if "secure" not in cookie.lower(): _add_finding(db,scan,"Low","Cookie missing Secure attribute","A response cookie was observed without Secure.","Add Secure to cookies transported over HTTPS.",url,category="Session",evidence=cookie[:240],cwe="CWE-614",status_code=response.status_code)
        if "httponly" not in cookie.lower(): _add_finding(db,scan,"Low","Cookie missing HttpOnly attribute","A response cookie was observed without HttpOnly.","Add HttpOnly to session and authentication cookies when JavaScript access is unnecessary.",url,category="Session",evidence=cookie[:240],cwe="CWE-1004",status_code=response.status_code)
    if re.search(r"(?i)(traceback|stack trace|exception at|sql syntax)",body): _add_finding(db,scan,"Medium","Verbose error disclosure observed","The page appears to expose diagnostic error text.","Disable verbose errors in production and return generic error pages.",url,category="Information Exposure",evidence="Diagnostic error marker detected",cwe="CWE-209",status_code=response.status_code)

def calculate_score(findings):
    penalty={"Critical":25,"High":15,"Medium":8,"Low":3,"Info":0}; seen=set(); total=0
    for f in findings:
        if f.confirmed is False: continue
        key=(f.title,f.severity)
        if key in seen: continue
        seen.add(key); total+=penalty.get(f.severity,0)
    return max(0,100-total)

def safe_scan(db:Session, scan:ScanRequest):
    started=time.monotonic(); scan.status="running"; scan.started_at=datetime.utcnow(); db.commit()
    base=scan.target.url; host=urlparse(base).hostname or ""; queue=deque([base]); visited=set(); requests=0
    headers={"User-Agent":"NEXVARY-VScan/0.5.0 Safe-Assessment"}
    with httpx.Client(timeout=8.0,follow_redirects=False,headers=headers) as client:
        while queue and len(visited)<MAX_PAGES and requests<MAX_REQUESTS:
            url=urldefrag(queue.popleft())[0]
            if url in visited or not same_scope(url,host): continue
            visited.add(url); _add_surface(db,scan,"endpoint",url,url,method="GET")
            for k,_ in parse_qsl(urlparse(url).query,keep_blank_values=True): _add_surface(db,scan,"parameter",k,url,method="GET")
            try:
                r=client.get(url); requests+=1
            except Exception as exc:
                _add_finding(db,scan,"Info","Endpoint fetch failed",f"The scanner could not fetch this endpoint: {type(exc).__name__}.","Confirm target availability and network path.",url,category="Scanner"); continue
            if REQUEST_DELAY: time.sleep(REQUEST_DELAY)
            location=r.headers.get("location")
            if 300<=r.status_code<400 and location:
                dest=urljoin(url,location)
                if not same_scope(dest,host): _add_finding(db,scan,"Info","Cross-scope redirect observed","A redirect points outside the approved hostname and was not followed.","Review whether the external redirect is expected.",url,category="Scope",evidence=dest,status_code=r.status_code)
                elif dest not in visited: queue.append(dest)
                continue
            ctype=r.headers.get("content-type","").lower(); body=r.text[:1_000_000] if ("text" in ctype or "html" in ctype or not ctype) else ""
            _analyze_response(db,scan,url,r,body)
            if "html" in ctype or "<html" in body[:500].lower():
                parser=SurfaceParser(url); parser.feed(body)
                for form in parser.forms:
                    _add_surface(db,scan,"form",form["action"],url,method=form["method"],detail=", ".join(i["name"] for i in form["inputs"]))
                    for i in form["inputs"]: _add_surface(db,scan,"parameter",i["name"],form["action"],method=form["method"],detail=i["type"])
                for script in parser.scripts: _add_surface(db,scan,"javascript",script,url,method="GET")
                for link in parser.links:
                    clean=urldefrag(link)[0]
                    if same_scope(clean,host) and not urlparse(clean).path.lower().endswith(STATIC_EXTENSIONS) and clean not in visited: queue.append(clean)
                    if "/api/" in urlparse(clean).path.lower(): _add_surface(db,scan,"api",clean,url,method="GET")
    scan.pages_crawled=len(visited); scan.requests_made=requests; db.flush(); scan.security_score=calculate_score(scan.findings); scan.status="completed"; scan.finished_at=datetime.utcnow(); scan.duration_ms=int((time.monotonic()-started)*1000); db.commit()
