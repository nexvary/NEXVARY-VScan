# NEXVARY VScan Stage 1750 — Portfolio Workspaces

Stage 1750 completes the portfolio and production-hardening integration introduced by the Stage 1750 foundation.

## Delivered

- Executive Security Portfolio on the main command center.
- Dedicated Targets workspace with ownership state and latest assessment score.
- Dedicated Scan Center with the complete authorized assessment ledger.
- Dedicated Reports archive with Executive, JSON and SARIF exports.
- Authenticated `/portfolio.json` export for portfolio-level metrics.
- Production release guard integrated at application startup.
- Configurable secure session cookies through `VSCAN_SECURE_COOKIES`.
- Explicit production mode through `VSCAN_PRODUCTION`; production startup is blocked when default credentials or a weak session secret remain.
- Stage 1750 live E2E coverage for portfolio, workspaces, trend, JSON and SARIF.

## Safety invariant

Ownership verification and NEXVARY approval remain mandatory before assessment execution. Existing same-host, public-address and request-budget guards remain unchanged. This milestone adds no exploit payloads, credential attacks, brute force, destructive fuzzing or state-changing attack probes.

## Production environment

Set at minimum:

- `VSCAN_PRODUCTION=1`
- `VSCAN_SECURE_COOKIES=1`
- `NEXVARY_ADMIN_PASSWORD=<strong non-default value>`
- `SESSION_SECRET=<random value of at least 32 characters>`

The application refuses production startup when these safety conditions are not met.
