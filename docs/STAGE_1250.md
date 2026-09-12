# NEXVARY VScan — Stage 1250

Release target: **v1.2.5**

## Objective

Stage 1250 strengthens analyst confidence and historical visibility while preserving the safe, authorized assessment model established by earlier releases.

## Delivered capabilities

1. **Risk Intelligence**
   - Deterministic severity weighting.
   - Confirmed-only score impact.
   - Deduplication by finding title + severity.
   - Category and severity summaries.

2. **Historical Trend Intelligence**
   - Automatically selects the previous completed assessment for the same target.
   - Computes new, resolved and persistent confirmed findings.
   - Potential findings are excluded from trend counts to avoid noisy comparisons.

3. **Asset Intelligence**
   - Classifies already-observed routes into admin-like, auth-like and upload/import/media groups.
   - Summarizes unique parameters, API hosts, JavaScript assets and source maps.
   - Classification is passive and does not cause additional state-changing requests.

4. **Technology Inventory**
   - Consolidates passive technology signals already recorded by the crawler.
   - Extracts explicit version hints when present in passive evidence.
   - Does not convert a version hint into a vulnerability claim by itself.

5. **Analyst Experience**
   - Stage 1250 intelligence cards in the assessment workspace.
   - Historical baseline information.
   - Technology inventory table.
   - Expanded executive report.
   - Extended JSON export with risk, asset, technology and trend sections.

## Safety gates retained

- Target ownership verification is mandatory.
- NEXVARY team approval is mandatory.
- Same-host scope is enforced.
- Private/reserved address guards remain active outside explicit local test mode.
- Request count, page count and delay limits remain enforced.
- No credential guessing, destructive fuzzing, exploitation chains or state-changing attack payloads are introduced.

## Release gate

The release is eligible to merge only after GitHub Actions completes:

- Python install/dependency resolution
- compileall
- pytest regression suite
- real Uvicorn end-to-end smoke test

The milestone is not considered released if CI is not green.
