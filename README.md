# NEXVARY VScan v0.8.5 — Stage 850

Professional authorized defensive web-security assessment platform for NEXVARY clients.

## Security workflow

Target creation → ownership verification → scan request → NEXVARY team approval → safe assessment → findings, passive intelligence, attack-surface map, report and JSON export.

## Stage 850 / v0.8.5

- Premium Security Command Center interface from v0.6.
- Hardened same-host request policy with DNS rebinding/private-address guard before assessment requests.
- Passive technology fingerprinting from headers, HTML metadata and observed front-end assets.
- JavaScript intelligence for observed API routes, source-map hints and client-side exposure indicators.
- Redacted potential-secret evidence: full candidate values are never copied into findings.
- robots.txt, sitemap.xml and security.txt discovery inside the already verified hostname.
- Form-risk checks for password forms using GET or plaintext HTTP.
- Expanded HTTP security checks: HSTS (HTTPS only), CSP presence and permissive directives, framing protection, Referrer-Policy, X-Content-Type-Options, Permissions-Policy, CORS, cookie Secure/HttpOnly/SameSite and mixed content.
- Route hints, source-map references, APIs, JavaScript assets, forms, parameters, endpoints and technologies surfaced in the assessment workspace.
- Conservative confidence model: potential findings do not lower the Security Score until confirmed.
- GitHub Actions CI and real Uvicorn smoke test remain mandatory before merge.

## Safety invariant

Ownership verification and explicit NEXVARY team approval remain mandatory. Assessment requests are same-host, rate-limited and capped. This release does **not** perform SQL injection, XSS exploitation, command execution, credential guessing, destructive fuzzing or state-changing attack payloads.

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

For milestone details see `docs/STAGE_850.md`.
