from __future__ import annotations
import re

LEVEL={"Critical":"error","High":"error","Medium":"warning","Low":"note","Info":"note"}


def _rule_id(finding)->str:
    raw=(getattr(finding,"cwe",None) or getattr(finding,"title","finding")).strip().lower()
    raw=re.sub(r"[^a-z0-9._-]+","-",raw).strip("-")
    return raw[:80] or "finding"


def build_sarif(scan, findings, version:str)->dict:
    rules={}; results=[]
    for finding in findings:
        if getattr(finding,"confirmed",True) is False:
            continue
        rid=_rule_id(finding)
        rules.setdefault(rid,{
            "id":rid,
            "name":getattr(finding,"title","Finding")[:120],
            "shortDescription":{"text":getattr(finding,"title","Finding")[:240]},
            "help":{"text":getattr(finding,"remediation","") or "Review and remediate this confirmed defensive finding."},
            "properties":{"category":getattr(finding,"category","Web Security") or "Web Security","cwe":getattr(finding,"cwe",None),"owasp":getattr(finding,"owasp",None)},
        })
        result={
            "ruleId":rid,
            "level":LEVEL.get(getattr(finding,"severity","Info"),"note"),
            "message":{"text":getattr(finding,"detail","") or getattr(finding,"title","Finding")},
            "properties":{
                "severity":getattr(finding,"severity","Info"),
                "confidence":getattr(finding,"confidence",None),
                "category":getattr(finding,"category",None),
                "confirmed":True,
            },
        }
        endpoint=getattr(finding,"endpoint",None)
        if endpoint:
            result["locations"]=[{"physicalLocation":{"artifactLocation":{"uri":endpoint}}}]
        results.append(result)
    return {
        "$schema":"https://json.schemastore.org/sarif-2.1.0.json",
        "version":"2.1.0",
        "runs":[{
            "tool":{"driver":{"name":"NEXVARY VScan","version":version,"informationUri":"https://nexvary.com/","rules":list(rules.values())}},
            "automationDetails":{"description":{"text":f"Authorized defensive assessment #{getattr(scan,'id','')}"}},
            "results":results,
        }],
    }
