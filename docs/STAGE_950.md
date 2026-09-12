# NEXVARY VScan — Stage 950

Stage 950 extends the defensive scanner with passive asset intelligence and browser-security posture analysis while preserving the verified-ownership and NEXVARY-approval gates.

## Added
- Passive dependency/version extraction from generator metadata and observed static asset names.
- Third-party host inventory without fetching external resources.
- security.txt field parsing into the attack-surface inventory.
- Passive Subresource Integrity (SRI) posture checks for third-party scripts/styles.
- Cross-Origin-Opener-Policy, Cross-Origin-Embedder-Policy and Cross-Origin-Resource-Policy visibility.
- Explicit plaintext-HTTP target finding.
- Stronger tests for version intelligence, third-party inventory, security.txt parsing and SRI behavior.

## Safety
No exploit payloads, credential guessing, destructive fuzzing, SQLi/XSS execution, command execution or cross-scope crawling are introduced by this stage.
