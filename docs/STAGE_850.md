# NEXVARY VScan — Stage 850 / v0.8.5

Stage 850 is a defensive-intelligence milestone. It strengthens discovery, passive analysis, scope safety, false-positive handling and reporting data without adding destructive exploitation.

## Delivered in this milestone

- DNS rebinding / private-address guard before outbound assessment requests.
- Passive technology fingerprinting from headers, HTML metadata and asset names.
- JavaScript intelligence for observed API routes, source-map hints and redacted client-secret indicators.
- robots.txt and sitemap.xml discovery inside the already verified hostname.
- Richer HTTP security checks including framing controls, Permissions-Policy, CSP quality, mixed content and cookie SameSite attributes.
- Form-risk analysis for password forms using GET or plaintext HTTP.
- Explicit confidence levels for findings and conservative scoring that excludes unconfirmed findings.
- Expanded unit tests covering the new analyzers and scope controls.

## Safety invariant

Target ownership verification and NEXVARY team approval remain mandatory before any assessment. Requests remain same-host, rate-limited and request-capped. The scanner does not perform SQL injection, XSS exploitation, command execution, credential attacks or state-changing fuzzing in this milestone.
