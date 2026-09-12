from types import SimpleNamespace
from app.risk_engine import calculate_score, confidence_label, risk_summary


def f(severity="Low", title="Finding", confirmed=True, category="HTTP Security"):
    return SimpleNamespace(severity=severity, title=title, confirmed=confirmed, category=category)


def test_score_is_conservative_and_deduplicated():
    findings = [
        f("High", "Confirmed A"),
        f("High", "Confirmed A"),
        f("Medium", "Confirmed B"),
        f("Critical", "Potential C", confirmed=False),
    ]
    assert calculate_score(findings) == 77


def test_risk_summary_separates_potential_findings():
    summary = risk_summary([
        f("High", "A", category="Session"),
        f("Low", "B", category="Session"),
        f("High", "C", confirmed=False, category="Client-Side Exposure"),
    ])
    assert summary["score"] == 82
    assert summary["confirmed"] == 2
    assert summary["potential"] == 1
    assert summary["severity"]["High"] == 1
    assert summary["top_categories"][0] == ("Session", 2)


def test_confidence_policy():
    assert confidence_label(True, "two corroborating signals", 2) == "High"
    assert confidence_label(True) == "Medium"
    assert confidence_label(False, "one signal", 1) == "Low"
    assert confidence_label(False, "corroborated", 2) == "Medium"
