# NEXVARY VScan — Stage 1500 / v1.5.0

Stage 1500 focuses on analyst workflow quality, remediation prioritization and CI/CD interoperability while preserving the authorized defensive operating model.

## Added

- Assessment Quality Intelligence with explicit coverage grading based on observed crawl breadth and mapped surface categories.
- Coverage disclaimer to prevent overclaiming that a successful scan proves an application is vulnerability-free.
- Deterministic remediation queue built only from confirmed findings, sorted by severity and deduplicated.
- SARIF 2.1.0 export for confirmed findings so authorized results can be consumed by compatible developer/security workflows.
- JSON export expanded with quality intelligence and remediation queue.
- Assessment workspace updated with coverage, remediation queue and SARIF action.
- Regression tests for quality grading, remediation prioritization and SARIF behavior.
- Live Uvicorn end-to-end gate updated to require Stage 1500 health, quality intelligence, remediation output and SARIF results.

## Safety invariant

Stage 1500 does not add exploitation, brute-force, destructive fuzzing, credential attacks or state-changing payloads. Ownership verification, NEXVARY approval, same-host scope controls, request caps and private-address protections remain mandatory.
