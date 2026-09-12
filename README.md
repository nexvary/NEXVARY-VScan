# NEXVARY VScan v1.2.5 — Stage 1250

Professional authorized defensive web-security assessment platform for NEXVARY clients.

## Security workflow

Target creation → ownership verification → scan request → NEXVARY team approval → safe assessment → findings, passive intelligence, attack-surface map, trend intelligence, executive report and JSON export.

## Stage 1250 / v1.2.5

Stage 1250 builds on the Stage 850 defensive scanner and adds a stronger analyst layer rather than more aggressive payload execution.

- Dedicated deterministic Risk Intelligence engine.
- Confirmed and potential findings are separated; potential findings do not reduce the Security Score.
- Historical scan comparison for the same verified target: new, resolved and persistent confirmed findings.
- Asset Intelligence classification for admin-like, authentication-like and upload/import/media routes already observed during the safe crawl.
- Passive Technology Inventory with version hints when the evidence contains an explicit version signal.
- API-host, parameter, JavaScript and source-map summaries.
- Stage 1250 intelligence embedded in the assessment workspace, executive report and JSON export.
- Premium Security Command Center UI with Stage 1250 status and responsive layouts.
- Hardened same-host request policy with DNS rebinding/private-address guard before assessment requests.
- Passive technology fingerprinting from headers, HTML metadata and observed front-end assets.
- JavaScript intelligence for observed API routes, source-map hints and redacted client-side exposure indicators.
- robots.txt, sitemap.xml and security.txt discovery inside the already verified hostname.
- HTTP security analysis for HSTS, CSP, framing protection, Referrer-Policy, X-Content-Type-Options, Permissions-Policy, CORS, cookie attributes and mixed content.
- GitHub Actions CI plus real Uvicorn end-to-end smoke testing before release merge.

## Safety invariant

Ownership verification and explicit NEXVARY team approval remain mandatory. Assessment requests are same-host, rate-limited and capped. Stage 1250 does **not** perform SQL injection exploitation, XSS exploitation, command execution, credential guessing, destructive fuzzing or state-changing attack payloads.

Technology version hints are inventory evidence only. VScan does not claim a CVE solely from a version-looking string.

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

Milestone details: `docs/STAGE_1250.md`.
