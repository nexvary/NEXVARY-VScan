from __future__ import annotations

DEFAULT_ADMIN_PASSWORD = "ChangeMe123!"
DEFAULT_SESSION_SECRET = "local-dev-only-change-in-production"


def release_guard(*, production_mode: bool, admin_password: str, session_secret: str, secure_cookies: bool) -> dict:
    issues: list[str] = []
    if admin_password == DEFAULT_ADMIN_PASSWORD:
        issues.append("default_admin_password")
    if session_secret == DEFAULT_SESSION_SECRET or len(session_secret) < 32:
        issues.append("weak_session_secret")
    if production_mode and not secure_cookies:
        issues.append("secure_cookies_disabled")
    return {
        "production_mode": production_mode,
        "secure_cookies": secure_cookies,
        "ready": not issues,
        "issues": issues,
        "status": "ready" if not issues else ("blocked" if production_mode else "development-warning"),
    }


def assert_production_ready(status: dict) -> None:
    if status.get("production_mode") and not status.get("ready"):
        issues = ", ".join(status.get("issues", [])) or "unknown"
        raise RuntimeError(f"Production release guard blocked startup: {issues}")
