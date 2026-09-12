from __future__ import annotations
from collections import Counter
import re
from urllib.parse import urlparse

_VERSION_RE = re.compile(r"(?<!\d)(\d+(?:\.\d+){1,3})(?!\d)")


def _value(item) -> str:
    return str(getattr(item, "value", "") or "")


def _category(item) -> str:
    return str(getattr(item, "category", "") or "")


def surface_summary(items) -> dict:
    items = list(items)
    counts = Counter(_category(i) for i in items)
    urls = [_value(i) for i in items if _category(i) in {"endpoint", "api", "route-hint", "form"}]
    lower_urls = [(u, u.lower()) for u in urls]
    admin = sorted({u for u, low in lower_urls if any(x in low for x in ("/admin", "/manage", "/console", "/dashboard"))})[:25]
    auth = sorted({u for u, low in lower_urls if any(x in low for x in ("/login", "/signin", "/oauth", "/auth", "/token"))})[:25]
    upload = sorted({u for u, low in lower_urls if any(x in low for x in ("/upload", "/import", "/attachment", "/media"))})[:25]
    api_hosts = Counter()
    for item in items:
        if _category(item) != "api":
            continue
        try:
            host = urlparse(_value(item)).hostname
        except Exception:
            host = None
        if host:
            api_hosts[host] += 1
    parameters = sorted({_value(i) for i in items if _category(i) == "parameter" and _value(i)})[:100]
    return {
        "counts": dict(counts),
        "admin_like_routes": admin,
        "auth_like_routes": auth,
        "upload_like_routes": upload,
        "unique_parameters": parameters,
        "api_hosts": api_hosts.most_common(10),
        "source_maps": counts.get("source-map", 0),
        "javascript_assets": counts.get("javascript", 0),
        "technologies": counts.get("technology", 0),
    }


def technology_inventory(items) -> list[dict]:
    inventory = []
    seen = set()
    for item in items:
        if _category(item) != "technology":
            continue
        name = _value(item).strip()
        detail = str(getattr(item, "detail", "") or "").strip()
        version = None
        match = _VERSION_RE.search(detail) or _VERSION_RE.search(name)
        if match:
            version = match.group(1)
        key = (name.lower(), version or "")
        if not name or key in seen:
            continue
        seen.add(key)
        inventory.append({"name": name, "version": version, "evidence": detail or "Passive signature"})
    inventory.sort(key=lambda x: (x["name"].lower(), x["version"] or ""))
    return inventory


def finding_signature(finding) -> tuple[str, str, str]:
    return (
        str(getattr(finding, "title", "") or "").strip(),
        str(getattr(finding, "severity", "Info") or "Info").strip(),
        str(getattr(finding, "endpoint", "") or "").strip(),
    )


def compare_findings(current_findings, previous_findings) -> dict:
    current = {finding_signature(f): f for f in current_findings if getattr(f, "confirmed", True) is not False}
    previous = {finding_signature(f): f for f in previous_findings if getattr(f, "confirmed", True) is not False}
    new_keys = sorted(set(current) - set(previous))
    resolved_keys = sorted(set(previous) - set(current))
    persistent_keys = sorted(set(current) & set(previous))

    def serialise(keys, source):
        out = []
        for key in keys[:100]:
            f = source[key]
            out.append({
                "title": key[0],
                "severity": key[1],
                "endpoint": key[2],
                "category": str(getattr(f, "category", "") or ""),
            })
        return out

    return {
        "new": serialise(new_keys, current),
        "resolved": serialise(resolved_keys, previous),
        "persistent": serialise(persistent_keys, current),
        "new_count": len(new_keys),
        "resolved_count": len(resolved_keys),
        "persistent_count": len(persistent_keys),
    }
