from __future__ import annotations
import re
from html import unescape
from urllib.parse import urljoin, urlparse

TECH_PATTERNS = [
    ("WordPress", re.compile(r"(?i)(wp-content|wp-includes|wordpress)")),
    ("Drupal", re.compile(r"(?i)(drupal-settings-json|/sites/default/files/|drupal)")),
    ("Joomla", re.compile(r"(?i)(/media/system/js/|joomla)")),
    ("Next.js", re.compile(r"(?i)(_next/static|__next_data__)")),
    ("React", re.compile(r"(?i)(react(?:\.production)?(?:\.min)?\.js|data-reactroot|__react)")),
    ("Vue.js", re.compile(r"(?i)(vue(?:\.global)?(?:\.prod)?(?:\.min)?\.js|__vue__)")),
    ("Angular", re.compile(r"(?i)(ng-version|angular(?:\.min)?\.js)")),
    ("jQuery", re.compile(r"(?i)jquery(?:[-.]([0-9]+(?:\.[0-9]+){1,3}))?(?:\.min)?\.js")),
    ("Bootstrap", re.compile(r"(?i)bootstrap(?:[-.]([0-9]+(?:\.[0-9]+){1,3}))?(?:\.min)?\.(?:js|css)")),
    ("ASP.NET", re.compile(r"(?i)(__viewstate|asp\.net|x-aspnet-version)")),
    ("Cloudflare", re.compile(r"(?i)(cf-ray|cloudflare)")),
]

JS_ROUTE_PATTERNS = [
    re.compile(r"(?P<q>['\"])(?P<route>/(?:api|graphql|rest|v[0-9]+|oauth|auth|webhook)[^'\"\s]{0,260})(?P=q)", re.I),
    re.compile(r"(?:fetch|axios\.(?:get|post|put|patch|delete))\s*\(\s*['\"](?P<route>[^'\"]{1,300})['\"]", re.I),
]

SECRET_PATTERNS = [
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("JWT token", re.compile(r"\beyJ[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}\b")),
    ("Private key material", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("Client-side API key assignment", re.compile(r"(?i)(?:api[_-]?key|secret|token)\s*[:=]\s*['\"]([^'\"]{16,160})['\"]")),
]

def fingerprint_technologies(headers: dict[str,str], body: str, asset_urls: list[str] | None = None) -> list[tuple[str,str]]:
    hay = "\n".join([body[:500_000], "\n".join(f"{k}:{v}" for k,v in headers.items()), "\n".join(asset_urls or [])])
    found: dict[str,str] = {}
    generator = re.search(r"(?is)<meta[^>]+name=['\"]generator['\"][^>]+content=['\"]([^'\"]+)['\"]", body)
    if generator:
        value = unescape(generator.group(1)).strip()[:120]
        if value: found[value] = "HTML generator metadata"
    for name, pattern in TECH_PATTERNS:
        m = pattern.search(hay)
        if m:
            detail = "Passive signature"
            if m.lastindex and m.group(1): detail = f"Version hint {m.group(1)}"
            found.setdefault(name, detail)
    server = headers.get("server")
    if server: found.setdefault(server[:120], "Server header")
    powered = headers.get("x-powered-by")
    if powered: found.setdefault(powered[:120], "X-Powered-By header")
    return sorted(found.items())

def extract_js_routes(source_url: str, text: str) -> list[str]:
    out=[]
    for pattern in JS_ROUTE_PATTERNS:
        for m in pattern.finditer(text[:1_000_000]):
            route=m.group("route").strip()
            if not route or route.startswith(("data:","javascript:")): continue
            absolute=urljoin(source_url, route)
            if absolute not in out: out.append(absolute)
            if len(out)>=120: return out
    return out

def source_map_hint(source_url: str, text: str) -> str | None:
    m=re.search(r"(?m)//[#@]\s*sourceMappingURL=([^\s]+)", text[-20_000:])
    return urljoin(source_url,m.group(1).strip()) if m else None

def redact_secret(value: str) -> str:
    value=value.strip()
    if len(value)<=8: return "***"
    return value[:4]+"…"+value[-4:]

def secret_indicators(text: str) -> list[tuple[str,str]]:
    results=[]
    sample=text[:1_000_000]
    for label,pattern in SECRET_PATTERNS:
        m=pattern.search(sample)
        if not m: continue
        raw=m.group(1) if m.lastindex else m.group(0)
        results.append((label,redact_secret(raw)))
    return results

def mixed_content_urls(page_url: str, body: str) -> list[str]:
    if urlparse(page_url).scheme!="https": return []
    urls=[]
    for m in re.finditer(r"(?i)(?:src|href|action)\s*=\s*['\"](http://[^'\"\s>]+)", body[:1_000_000]):
        if m.group(1) not in urls: urls.append(m.group(1))
        if len(urls)>=25: break
    return urls
