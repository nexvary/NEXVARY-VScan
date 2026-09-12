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

ASSET_VERSION_PATTERNS = [
    ("jQuery", re.compile(r"(?i)jquery(?:[-.]|%20)?v?([0-9]+(?:\.[0-9]+){1,3})(?:\.min)?\.js")),
    ("Bootstrap", re.compile(r"(?i)bootstrap(?:[-.]|%20)?v?([0-9]+(?:\.[0-9]+){1,3})(?:\.bundle)?(?:\.min)?\.(?:js|css)")),
    ("Vue.js", re.compile(r"(?i)vue(?:[-.]|%20)?v?([0-9]+(?:\.[0-9]+){1,3})(?:\.global|\.prod|\.min)*\.js")),
    ("React", re.compile(r"(?i)react(?:[-.]|%20)?v?([0-9]+(?:\.[0-9]+){1,3})(?:\.production|\.min)*\.js")),
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


def extract_asset_versions(body: str, asset_urls: list[str] | None = None) -> list[tuple[str,str,str]]:
    results: list[tuple[str,str,str]] = []
    seen=set()
    generator = re.search(r"(?is)<meta[^>]+name=['\"]generator['\"][^>]+content=['\"]([^'\"]+)['\"]", body)
    if generator:
        value=unescape(generator.group(1)).strip()
        m=re.match(r"(.+?)\s+([0-9]+(?:\.[0-9]+){1,3})(?:\s|$)",value)
        if m:
            key=(m.group(1).strip(),m.group(2),"generator")
            if key not in seen: results.append(key); seen.add(key)
    for url in asset_urls or []:
        path=urlparse(url).path.rsplit("/",1)[-1]
        for name,pattern in ASSET_VERSION_PATTERNS:
            m=pattern.search(path)
            if m:
                key=(name,m.group(1),url)
                if key not in seen: results.append(key); seen.add(key)
    return results[:80]


def third_party_hosts(page_url: str, asset_urls: list[str] | None = None) -> list[str]:
    page_host=(urlparse(page_url).hostname or "").lower().rstrip(".")
    hosts=[]
    for asset in asset_urls or []:
        host=(urlparse(asset).hostname or "").lower().rstrip(".")
        if host and host!=page_host and host not in hosts: hosts.append(host)
    return hosts[:80]


def parse_security_txt(text: str) -> list[tuple[str,str]]:
    allowed={"contact","expires","encryption","acknowledgments","preferred-languages","canonical","policy","hiring"}
    out=[]
    for raw in text.splitlines():
        line=raw.strip()
        if not line or line.startswith("#") or ":" not in line: continue
        key,value=line.split(":",1); key=key.strip().lower(); value=value.strip()
        if key in allowed and value:
            out.append((key,value[:500]))
        if len(out)>=40: break
    return out


def browser_isolation_headers(headers: dict[str,str]) -> dict[str,str]:
    wanted=("cross-origin-opener-policy","cross-origin-embedder-policy","cross-origin-resource-policy")
    return {k:headers[k] for k in wanted if headers.get(k)}


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
