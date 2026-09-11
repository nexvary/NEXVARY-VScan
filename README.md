# NEXVARY VScan v0.5.0

Professional authorized defensive web-security assessment platform for NEXVARY clients.

## Security workflow

Target creation → ownership verification → scan request → NEXVARY team approval → safe assessment → findings, attack-surface map, report and JSON export.

## v0.5.0

- Modularized backend (`config`, `db`, `models`, `security`, `scanner`, `main`).
- GitHub Actions CI on Python 3.13.
- Live end-to-end smoke test starts a real Uvicorn server and an authorized local target.
- Ownership verification failures now return to the dashboard with an actionable message instead of raw JSON.
- Copy-token control and clearer verification instructions.
- Passive/low-impact crawler, HTTP header/CORS/cookie/error-disclosure checks, forms, parameters, API references and JavaScript surface mapping.
- Same-host scope restriction and NEXVARY approval remain mandatory.

## Run locally

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --host 127.0.0.1 --port 8765
```

Open `http://127.0.0.1:8765/login`.

Local test login: `admin` / `ChangeMe123!`. Set `NEXVARY_ADMIN_PASSWORD` and `SESSION_SECRET` before production.

## Tests

```bash
pytest -q
python smoke_test.py
```

This release is deliberately non-destructive. It does not submit SQL injection, XSS, command-execution, credential-guessing or state-changing payloads.
