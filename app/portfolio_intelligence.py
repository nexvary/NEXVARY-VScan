from __future__ import annotations
from collections import Counter


def portfolio_summary(targets, scans) -> dict:
    verified = sum(1 for t in targets if getattr(t, "verified", False))
    completed = [s for s in scans if getattr(s, "status", "") == "completed"]
    scored = [s for s in completed if getattr(s, "security_score", None) is not None]
    latest_by_target = {}
    for scan in sorted(completed, key=lambda s: getattr(s, "id", 0), reverse=True):
        tid = getattr(scan, "target_id", None)
        if tid not in latest_by_target:
            latest_by_target[tid] = scan
    latest_scores = [s.security_score for s in latest_by_target.values() if s.security_score is not None]
    status_counts = Counter(getattr(s, "status", "unknown") for s in scans)
    return {
        "targets_total": len(targets),
        "targets_verified": verified,
        "verification_rate": round((verified / len(targets)) * 100) if targets else 0,
        "assessments_total": len(scans),
        "completed": len(completed),
        "average_completed_score": round(sum(s.security_score for s in scored) / len(scored)) if scored else None,
        "current_portfolio_score": round(sum(latest_scores) / len(latest_scores)) if latest_scores else None,
        "status_counts": dict(status_counts),
        "targets_with_baseline": len(latest_by_target),
    }


def score_band(score):
    if score is None:
        return "unknown"
    if score >= 90:
        return "strong"
    if score >= 75:
        return "managed"
    if score >= 60:
        return "needs-attention"
    return "high-priority"
