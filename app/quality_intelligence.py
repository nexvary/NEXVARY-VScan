from __future__ import annotations
from collections import Counter

SEVERITY_PRIORITY={"Critical":0,"High":1,"Medium":2,"Low":3,"Info":4}


def remediation_queue(findings, limit:int=12)->list[dict]:
    """Build a deterministic remediation queue from confirmed findings only."""
    confirmed=[f for f in findings if getattr(f,"confirmed",True) is not False]
    ordered=sorted(confirmed,key=lambda f:(SEVERITY_PRIORITY.get(getattr(f,"severity","Info"),9),getattr(f,"title",""),getattr(f,"endpoint","") or ""))
    out=[]; seen=set()
    for finding in ordered:
        key=(getattr(finding,"title",""),getattr(finding,"severity",""),getattr(finding,"category","") or "")
        if key in seen: continue
        seen.add(key)
        out.append({
            "severity":getattr(finding,"severity","Info"),
            "title":getattr(finding,"title","Untitled finding"),
            "category":getattr(finding,"category","Other") or "Other",
            "endpoint":getattr(finding,"endpoint",None),
            "remediation":getattr(finding,"remediation","") or "Review and remediate the confirmed observation.",
            "cwe":getattr(finding,"cwe",None),
        })
        if len(out)>=limit: break
    return out


def assessment_quality(scan, findings, surfaces)->dict:
    """Explain assessment coverage without claiming exploit validation."""
    categories=Counter(getattr(s,"category","") for s in surfaces)
    confirmed=sum(1 for f in findings if getattr(f,"confirmed",True) is not False)
    potential=len(findings)-confirmed
    pages=max(int(getattr(scan,"pages_crawled",0) or 0),0)
    requests=max(int(getattr(scan,"requests_made",0) or 0),0)
    signals=0
    signals += 2 if pages>=5 else 1 if pages>0 else 0
    signals += 2 if requests>=10 else 1 if requests>0 else 0
    signals += 1 if categories.get("javascript",0)>0 else 0
    signals += 1 if categories.get("api",0)>0 else 0
    signals += 1 if categories.get("technology",0)>0 else 0
    signals += 1 if categories.get("form",0)>0 else 0
    grade="High" if signals>=7 else "Medium" if signals>=4 else "Limited"
    return {
        "coverage_grade":grade,
        "coverage_signals":signals,
        "pages":pages,
        "requests":requests,
        "confirmed_findings":confirmed,
        "potential_findings":potential,
        "surface_categories":sum(1 for _,count in categories.items() if count),
        "disclaimer":"Coverage indicates observed assessment breadth, not proof that the application is vulnerability-free.",
    }
