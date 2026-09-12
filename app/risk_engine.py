from __future__ import annotations
from collections import Counter

SEVERITY_WEIGHT = {"Critical": 25, "High": 15, "Medium": 8, "Low": 3, "Info": 0}
CONFIDENCE_WEIGHT = {"High": 1.0, "Medium": 0.65, "Low": 0.35}


def finding_key(finding) -> tuple[str, str]:
    """Stable deduplication key for risk scoring."""
    return (str(getattr(finding, "title", "")).strip(), str(getattr(finding, "severity", "Info")))


def calculate_score(findings) -> int:
    """Conservative 0-100 score. Potential/unconfirmed findings never reduce score."""
    seen: set[tuple[str, str]] = set()
    penalty = 0
    for finding in findings:
        if getattr(finding, "confirmed", True) is False:
            continue
        key = finding_key(finding)
        if key in seen:
            continue
        seen.add(key)
        penalty += SEVERITY_WEIGHT.get(str(getattr(finding, "severity", "Info")), 0)
    return max(0, 100 - penalty)


def risk_summary(findings) -> dict:
    confirmed = [f for f in findings if getattr(f, "confirmed", True) is not False]
    potential = [f for f in findings if getattr(f, "confirmed", True) is False]
    severity = Counter(str(getattr(f, "severity", "Info")) for f in confirmed)
    categories = Counter(str(getattr(f, "category", "Other") or "Other") for f in confirmed)
    return {
        "score": calculate_score(findings),
        "confirmed": len(confirmed),
        "potential": len(potential),
        "severity": {name: severity.get(name, 0) for name in ("Critical", "High", "Medium", "Low", "Info")},
        "top_categories": categories.most_common(5),
    }


def confidence_label(confirmed: bool, evidence: str = "", signal_count: int = 1) -> str:
    """Keep passive heuristics conservative while allowing corroborated evidence to rank higher."""
    if confirmed and evidence and signal_count >= 2:
        return "High"
    if confirmed:
        return "Medium"
    if evidence and signal_count >= 2:
        return "Medium"
    return "Low"
