from __future__ import annotations
import re, time
from collections import deque
from datetime import datetime
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urldefrag, urljoin, urlparse
import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session
from .config import MAX_PAGES, MAX_REQUESTS, REQUEST_DELAY, ALLOW_PRIVATE_TEST_TARGETS, VERSION
from .intelligence import (
    browser_isolation_headers, extract_asset_versions, extract_js_routes,
    fingerprint_technologies, mixed_content_urls, parse_security_txt,
    secret_indicators, source_map_hint, third_party_hosts,
)
from .models import Finding, ScanRequest, SurfaceItem
from .security import is_public_host, same_scope

STATIC_EXTENSIONS=(".png",".jpg",".jpeg",".gif",".svg",".css",".woff",".woff2",".pdf",".zip",".mp4",".mp3",".ico")

class SurfaceParser(HTMLParser):
    def __init__(self, base_url:str):
        super().__init__(convert_charrefs=True)
        self.base_url=base_url
        self.links=[]; self.scripts=[]; self.styles=[]; self.forms=[]
        self.script_meta=[]; self.style_meta=[]; self._form=None
    def handle_starttag(self, tag, attrs):
        d={str(k).lower():(v or "") for k,v in attrs}; tag=tag.lower()
        if tag=="a" and d.get("href"):
            self.links.append(urljoin(self.base_url,d["href"]))
        elif tag=="script" and d.get("src"):
            url=urljoin(self.base_url,d["src"]); self.scripts.append(url)
            self.script_meta.append({"url":url,"integrity":d.get("integrity","")})
        elif tag=="link" and d.get("href"):
            url=urljoin(self.base_url,d["href"]); self.styles.append(url)
            rel=d.get("rel","").lower()
            if "stylesheet" in rel: self.style_meta.append({"url":url,"integrity":d.get("integrity","")})
        elif tag=="form":
            self._form={"action":urljoin(self.base_url,d.get("action") or self.base_url),"method":(d.get("method") or "GET").upper(),"inputs":[]}
        elif tag in {"input","select","textarea"} and self._form is not None and d.get("name"):
            self._form["inputs"].append({"name":d["name"],"type":d.get("type",tag).lower()})
    def handle_endtag(self, tag):
        if tag.lower()=="form" and self._form is not None:
            self.forms.append(self._form); self._form=None

def _add_finding(db:Session,scan:ScanRequest,severity,title,detail,remediation,endpoint,confirmed=True,category="Web Security",evidence="",cwe=None,owasp=None,status_code=None,confidence=None):
    exists=db.scalar(select(Finding).where(Finding.scan_request_id==scan.id,Finding.title==title,Finding.endpoint==endpoint))
    if not exists:
        db.add(Finding(scan_request_id=scan.id,severity=severity,title=title,detail=detail,remediation=remediation,endpoint=endpoint,confirmed=confirmed,confidence=confidence or ("High" if confirmed else "Low"),category=category,evidence=evidence,cwe=cwe,owasp=owasp,status_code=status_code))

def _add_surface(db:Session,scan:ScanRequest,category,value,source=None,method=None,detail=""):
    value=value[:900]; source=source[:900] if source else None
    exists=db.scalar(select(SurfaceItem).where(SurfaceItem.scan_request_id==scan.id,SurfaceItem.category==category,SurfaceItem.value==value,SurfaceItem.source_endpoint==source))
    if not exists: db.add(SurfaceItem(scan_request_id=scan.id,category=category,value=value,source_endpoint=source,method=method,detail=detail[:4000]))

def _safe_host(host:str)->bool:
    return ALLOW_PRIVATE_TEST_TARGETS or is_public_host(host)

def _request(client:httpx.Client,url:str,host:str):
    if not same_scope(url,host): raise ValueError("cross-scope request blocked")
    if not _safe_host(host): raise ValueError("target resolved to a non-public address")
    return client.get(url)

def _analyze_response(db:Session,scan:ScanRequest,url:str,response:httpx.Response,body:str,assets:list[str]|None=None):
    headers={k.lower():v for k,v in response.headers.items()}; scheme=urlparse(url).scheme
    checks=[
        ("content-security-policy","Medium","Content-Security-Policy header missing","Add a restrictive CSP tailored to the application.","CWE-693"),
        ("x-content-type-options","Low","X-Content-Type-Options header missing","Set X-Content-Type-Options: nosniff.","CWE-693"),
        ("referrer-policy","Low","Referrer-Policy header missing","Set a suitable Referrer-Policy.","CWE-200"),
        ("permissions-policy","Info","Permissions-Policy header missing","Define an explicit Permissions-Policy for browser capabilities used by the application.","CWE-693"),
    ]
    if scheme=="https":
        checks.append(("strict-transport-security","Medium","HSTS header missing","Enable HSTS after confirming HTTPS-only operation.","CWE-319"))
    else:
        _add_finding(db,scan,"Medium","Plaintext HTTP transport observed","The approved target is being assessed over HTTP rather than HTTPS.","Deploy HTTPS for the application and redirect HTTP traffic to HTTPS.",url,category="Transport Security",evidence=f"HTTP {response.status_code}",cwe="CWE-319",status_code=response.status_code)
    for key,sev,title,rem,cwe in checks:
        if key not in headers: _add_finding(db,scan,sev,title,f"The response did not include {key}.",rem,url,category="HTTP Security",evidence=f"HTTP {response.status_code}",cwe=cwe,status_code=response.status_code)
    csp=headers.get("content-security-policy","")
    if csp and ("'unsafe-inline'" in csp or "'unsafe-eval'" in csp):
        _add_finding(db,scan,"Low","CSP contains permissive script directives","The observed Content-Security-Policy contains unsafe-inline and/or unsafe-eval.","Remove unsafe directives where practical and prefer nonces or hashes.",url,confirmed=False,confidence="Medium",category="HTTP Security",evidence=csp[:280],cwe="CWE-693",status_code=response.status_code)
    if "x-frame-options" not in headers and "frame-ancestors" not in csp.lower():
        _add_finding(db,scan,"Low","Framing protection not observed","Neither X-Frame-Options nor CSP frame-ancestors was observed.","Define frame-ancestors in CSP or X-Frame-Options where framing is not required.",url,category="HTTP Security",cwe="CWE-1021",status_code=response.status_code)
    origin=headers.get("access-control-allow-origin")
    creds=headers.get("access-control-allow-credentials","").lower()=="true"
    if origin=="*":
        sev="Medium" if creds else "Low"
        _add_finding(db,scan,sev,"Wildcard CORS policy observed","The response advertises a wildcard Access-Control-Allow-Origin policy.","Restrict allowed origins to trusted application origins where cross-origin access is required.",url,category="CORS",evidence=f"Access-Control-Allow-Origin: *; credentials={creds}",cwe="CWE-942",status_code=response.status_code)
    for name,detail in fingerprint_technologies(headers,body,assets or []):
        _add_surface(db,scan,"technology",name,url,detail=detail)
    for name,version,source in extract_asset_versions(body,assets or []):
        _add_surface(db,scan,"dependency",f"{name} {version}",url,method="OBSERVED",detail=f"Passive version evidence: {source[:300]}")
    for policy,value in browser_isolation_headers(headers).items():
        _add_surface(db,scan,"browser-policy",f"{policy}: {value}",url,method="HEADER",detail="Browser isolation policy observed")
    for cookie in response.headers.get_list("set-cookie"):
        lower=cookie.lower()
        if scheme=="https" and "secure" not in lower: _add_finding(db,scan,"Low","Cookie missing Secure attribute","A response cookie was observed without Secure.","Add Secure to cookies transported over HTTPS.",url,category="Session",evidence=cookie[:240],cwe="CWE-614",status_code=response.status_code)
        if "httponly" not in lower: _add_finding(db,scan,"Low","Cookie missing HttpOnly attribute","A response cookie was observed without HttpOnly.","Add HttpOnly to session and authentication cookies when JavaScript access is unnecessary.",url,category="Session",evidence=cookie[:240],cwe="CWE-1004",status_code=response.status_code)
        if "samesite" not in lower: _add_finding(db,scan,"Info","Cookie missing SameSite attribute","A response cookie was observed without an explicit SameSite attribute.","Set SameSite=Lax or Strict where compatible, or SameSite=None; Secure when cross-site use is required.",url,category="Session",evidence=cookie[:240],cwe="CWE-1275",status_code=response.status_code)
    if re.search(r"(?i)(traceback|stack trace|exception at|sql syntax|fatal error:|undefined index:)",body):
        _add_finding(db,scan,"Medium","Verbose error disclosure observed","The page appears to expose diagnostic error text.","Disable verbose errors in production and return generic error pages.",url,category="Information Exposure",evidence="Diagnostic error marker detected",cwe="CWE-209",status_code=response.status_code)
    mixed=mixed_content_urls(url,body)
    if mixed: _add_finding(db,scan,"Medium","Mixed content references observed","An HTTPS page references one or more HTTP resources.","Serve all active and passive page resources over HTTPS.",url,category="Transport Security",evidence=", ".join(mixed[:3]),cwe="CWE-319",status_code=response.status_code)

def _analyze_external_assets(db:Session,scan:ScanRequest,page_url:str,parser:SurfaceParser):
    assets=parser.scripts+parser.styles
    for host in third_party_hosts(page_url,assets):
        _add_surface(db,scan,"third-party-host",host,page_url,method="OBSERVED",detail="Referenced by page; external resource was not fetched")
    page_host=(urlparse(page_url).hostname or "").lower().rstrip(".")
    for item in parser.script_meta+parser.style_meta:
        host=(urlparse(item["url"]).hostname or "").lower().rstrip(".")
        if host and host!=page_host and not item.get("integrity"):
            _add_finding(db,scan,"Info","Third-party resource without Subresource Integrity", "A third-party script or stylesheet is referenced without an integrity attribute. This is a passive posture observation.","Where practical, pin third-party static assets and add an appropriate SRI integrity hash plus compatible CORS settings.",item["url"],confirmed=False,confidence="Medium",category="Supply Chain",evidence=f"Referenced by {page_url}",cwe="CWE-353")

def _analyze_form(db:Session,scan:ScanRequest,page_url:str,form:dict):
    password=any(i.get("type")=="password" for i in form["inputs"])
    if not password: return
    if form["method"]=="GET": _add_finding(db,scan,"Medium","Password form uses GET","A form containing a password input submits with GET, which can expose credentials in URLs and logs.","Use POST over HTTPS for credential submission.",form["action"],category="Authentication",evidence=f"Source: {page_url}",cwe="CWE-598")
    if urlparse(form["action"]).scheme!="https": _add_finding(db,scan,"High","Password form submits over plaintext HTTP","A password-bearing form action is not HTTPS.","Submit credentials only to HTTPS endpoints and redirect HTTP to HTTPS.",form["action"],category="Authentication",evidence=f"Source: {page_url}",cwe="CWE-319")

def _analyze_javascript(db:Session,scan:ScanRequest,script_url:str,text:str,host:str):
    for route in extract_js_routes(script_url,text):
        if same_scope(route,host): _add_surface(db,scan,"api",route,script_url,method="OBSERVED",detail="Client-side route reference")
    smap=source_map_hint(script_url,text)
    if smap and same_scope(smap,host): _add_surface(db,scan,"source-map",smap,script_url,method="OBSERVED",detail="Source map reference in JavaScript")
    for label,redacted in secret_indicators(text):
        _add_finding(db,scan,"High","Potential client-side secret indicator",f"Client-side JavaScript contains a pattern resembling {label}. The value is redacted and requires analyst confirmation.","Review the source, rotate exposed credentials if confirmed, and move secrets to server-side storage.",script_url,confirmed=False,confidence="Medium",category="Client-Side Exposure",evidence=f"{label}: {redacted}",cwe="CWE-798")

def _discover_standard_metadata(db:Session,scan:ScanRequest,client:httpx.Client,base:str,host:str,queue:deque,requests:int)->int:
    for path,category in [("/robots.txt","robots"),("/sitemap.xml","sitemap"),("/.well-known/security.txt","security-contact")]:
        if requests>=MAX_REQUESTS: break
        url=urljoin(base+"/",path.lstrip("/"))
        try: r=_request(client,url,host); requests+=1
        except Exception: continue
        if REQUEST_DELAY: time.sleep(REQUEST_DELAY)
        if r.status_code!=200: continue
        text=r.text[:500_000]; _add_surface(db,scan,category,url,base,method="GET",detail=f"HTTP {r.status_code}")
        if category=="robots":
            for line in text.splitlines():
                if ":" not in line: continue
                key,value=line.split(":",1); key=key.strip().lower(); value=value.strip()
                if key in {"allow","disallow"} and value.startswith("/"):
                    candidate=urljoin(base,value); _add_surface(db,scan,"route-hint",candidate,url,method="ROBOTS",detail=key)
                elif key=="sitemap" and value:
                    candidate=urljoin(base,value)
                    if same_scope(candidate,host): queue.append(candidate)
        elif category=="sitemap":
            for loc in re.findall(r"(?is)<loc>\s*([^<]+)\s*</loc>",text):
                candidate=loc.strip()
                if same_scope(candidate,host):
                    _add_surface(db,scan,"route-hint",candidate,url,method="SITEMAP")
                    if not urlparse(candidate).path.lower().endswith(STATIC_EXTENSIONS): queue.append(candidate)
        elif category=="security-contact":
            for field,value in parse_security_txt(text):
                _add_surface(db,scan,"security-txt",f"{field}: {value}",url,method="METADATA",detail="security.txt field")
    return requests

def calculate_score(findings):
    penalty={"Critical":25,"High":15,"Medium":8,"Low":3,"Info":0}; seen=set(); total=0
    for f in findings:
        if f.confirmed is False: continue
        key=(f.title,f.severity)
        if key in seen: continue
        seen.add(key); total+=penalty.get(f.severity,0)
    return max(0,100-total)

def safe_scan(db:Session,scan:ScanRequest):
    started=time.monotonic(); scan.status="running"; scan.started_at=datetime.utcnow(); db.commit()
    base=scan.target.url; host=urlparse(base).hostname or ""; queue=deque([base]); visited=set(); requests=0; fetched_scripts=set()
    headers={"User-Agent":f"NEXVARY-VScan/{VERSION} Safe-Assessment"}
    if not _safe_host(host):
        scan.status="rejected"; scan.finished_at=datetime.utcnow(); _add_finding(db,scan,"Info","Assessment blocked by network scope guard","The verified hostname currently resolves to a private, reserved or otherwise non-public address.","Confirm DNS and approved scope before retrying.",base,category="Scanner Safety"); db.commit(); return
    with httpx.Client(timeout=8.0,follow_redirects=False,headers=headers) as client:
        requests=_discover_standard_metadata(db,scan,client,base,host,queue,requests)
        while queue and len(visited)<MAX_PAGES and requests<MAX_REQUESTS:
            url=urldefrag(queue.popleft())[0]
            if url in visited or not same_scope(url,host): continue
            visited.add(url); _add_surface(db,scan,"endpoint",url,url,method="GET")
            for k,_ in parse_qsl(urlparse(url).query,keep_blank_values=True): _add_surface(db,scan,"parameter",k,url,method="GET")
            try: r=_request(client,url,host); requests+=1
            except Exception as exc:
                _add_finding(db,scan,"Info","Endpoint fetch failed",f"The scanner could not fetch this endpoint: {type(exc).__name__}.","Confirm target availability and network path.",url,category="Scanner"); continue
            if REQUEST_DELAY: time.sleep(REQUEST_DELAY)
            location=r.headers.get("location")
            if 300<=r.status_code<400 and location:
                dest=urljoin(url,location)
                if not same_scope(dest,host): _add_finding(db,scan,"Info","Cross-scope redirect observed","A redirect points outside the approved hostname and was not followed.","Review whether the external redirect is expected.",url,category="Scope",evidence=dest,status_code=r.status_code)
                elif dest not in visited: queue.append(dest)
                continue
            ctype=r.headers.get("content-type","").lower(); body=r.text[:1_000_000] if ("text" in ctype or "html" in ctype or "javascript" in ctype or not ctype) else ""
            parser=None; assets=[]
            if "html" in ctype or "<html" in body[:500].lower():
                parser=SurfaceParser(url); parser.feed(body); assets=parser.scripts+parser.styles
            _analyze_response(db,scan,url,r,body,assets)
            if parser:
                _analyze_external_assets(db,scan,url,parser)
                for form in parser.forms:
                    _add_surface(db,scan,"form",form["action"],url,method=form["method"],detail=", ".join(i["name"] for i in form["inputs"])); _analyze_form(db,scan,url,form)
                    for i in form["inputs"]: _add_surface(db,scan,"parameter",i["name"],form["action"],method=form["method"],detail=i["type"])
                for script in parser.scripts:
                    _add_surface(db,scan,"javascript",script,url,method="GET")
                    if script in fetched_scripts or requests>=MAX_REQUESTS or not same_scope(script,host): continue
                    fetched_scripts.add(script)
                    try: jsr=_request(client,script,host); requests+=1
                    except Exception: continue
                    if REQUEST_DELAY: time.sleep(REQUEST_DELAY)
                    if jsr.status_code==200 and len(jsr.content)<=1_500_000:
                        _analyze_javascript(db,scan,script,jsr.text[:1_000_000],host)
                for link in parser.links:
                    clean=urldefrag(link)[0]
                    if same_scope(clean,host) and not urlparse(clean).path.lower().endswith(STATIC_EXTENSIONS) and clean not in visited: queue.append(clean)
                    if "/api/" in urlparse(clean).path.lower() or "/graphql" in urlparse(clean).path.lower(): _add_surface(db,scan,"api",clean,url,method="GET")
    scan.pages_crawled=len(visited); scan.requests_made=requests; db.flush(); scan.security_score=calculate_score(scan.findings); scan.status="completed"; scan.finished_at=datetime.utcnow(); scan.duration_ms=int((time.monotonic()-started)*1000); db.commit()
