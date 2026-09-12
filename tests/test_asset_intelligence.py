from types import SimpleNamespace
from app.asset_intelligence import compare_findings, surface_summary, technology_inventory


def item(category, value, detail=""):
    return SimpleNamespace(category=category, value=value, detail=detail)


def finding(title, severity="Low", endpoint="https://example.com", confirmed=True, category="HTTP Security"):
    return SimpleNamespace(title=title, severity=severity, endpoint=endpoint, confirmed=confirmed, category=category)


def test_surface_summary_classifies_routes_without_requesting_them():
    summary = surface_summary([
        item("endpoint", "https://example.com/admin"),
        item("endpoint", "https://example.com/login"),
        item("form", "https://example.com/upload"),
        item("parameter", "return_url"),
        item("api", "https://example.com/api/v1/users"),
        item("javascript", "https://example.com/app.js"),
        item("source-map", "https://example.com/app.js.map"),
    ])
    assert summary["admin_like_routes"] == ["https://example.com/admin"]
    assert summary["auth_like_routes"] == ["https://example.com/login"]
    assert summary["upload_like_routes"] == ["https://example.com/upload"]
    assert summary["unique_parameters"] == ["return_url"]
    assert summary["api_hosts"] == [("example.com", 1)]
    assert summary["javascript_assets"] == 1
    assert summary["source_maps"] == 1


def test_technology_inventory_extracts_version_hints():
    inventory = technology_inventory([
        item("technology", "jQuery", "Version hint 3.7.1"),
        item("technology", "nginx/1.26.2", "Server header"),
        item("endpoint", "https://example.com"),
    ])
    assert {x["name"]: x["version"] for x in inventory} == {"jQuery": "3.7.1", "nginx/1.26.2": "1.26.2"}


def test_compare_findings_tracks_new_resolved_and_persistent_confirmed_only():
    previous = [finding("HSTS missing", "Medium", "/"), finding("Old issue", "Low", "/a")]
    current = [finding("HSTS missing", "Medium", "/"), finding("New issue", "High", "/b"), finding("Potential", "Critical", "/c", confirmed=False)]
    trend = compare_findings(current, previous)
    assert trend["new_count"] == 1
    assert trend["resolved_count"] == 1
    assert trend["persistent_count"] == 1
    assert trend["new"][0]["title"] == "New issue"
    assert trend["resolved"][0]["title"] == "Old issue"
