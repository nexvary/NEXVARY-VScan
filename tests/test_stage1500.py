from types import SimpleNamespace
from app.quality_intelligence import assessment_quality, remediation_queue
from app.sarif_export import build_sarif


def finding(severity="Low",title="A",confirmed=True,category="HTTP Security",endpoint="https://example.com",cwe="CWE-693"):
    return SimpleNamespace(severity=severity,title=title,confirmed=confirmed,category=category,endpoint=endpoint,cwe=cwe,owasp=None,confidence="High",detail="detail",remediation="fix")


def test_remediation_queue_prioritizes_confirmed_and_deduplicates():
    items=remediation_queue([
        finding("Low","L"),
        finding("High","H"),
        finding("High","H"),
        finding("Critical","Potential",confirmed=False),
    ])
    assert [x["title"] for x in items]==["H","L"]


def test_assessment_quality_reports_coverage_without_overclaiming():
    scan=SimpleNamespace(pages_crawled=8,requests_made=20)
    surfaces=[SimpleNamespace(category=x) for x in ["javascript","api","technology","form","endpoint"]]
    q=assessment_quality(scan,[finding("Medium","M"),finding("High","P",confirmed=False)],surfaces)
    assert q["coverage_grade"]=="High"
    assert q["confirmed_findings"]==1 and q["potential_findings"]==1
    assert "not proof" in q["disclaimer"]


def test_sarif_exports_only_confirmed_findings():
    scan=SimpleNamespace(id=9)
    sarif=build_sarif(scan,[finding("High","Confirmed"),finding("Critical","Potential",confirmed=False)],"1.5.0")
    run=sarif["runs"][0]
    assert sarif["version"]=="2.1.0"
    assert run["tool"]["driver"]["version"]=="1.5.0"
    assert len(run["results"])==1
    assert run["results"][0]["level"]=="error"
