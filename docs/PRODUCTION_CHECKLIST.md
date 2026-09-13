# NEXVARY VScan Production Checklist

Before enabling production mode:

1. Set `NEXVARY_ADMIN_PASSWORD` to a strong non-default value.
2. Set `SESSION_SECRET` to a random value of at least 32 characters.
3. Set `VSCAN_PRODUCTION=1`.
4. Set `VSCAN_SECURE_COOKIES=1` and serve the application behind HTTPS.
5. Keep ownership verification and NEXVARY approval enabled; do not bypass them.
6. Keep public-address and same-host scanner guards enabled.
7. Run `pytest -q` and `python smoke_test.py` before release.

Production startup is intentionally blocked by the release guard when credential, session-secret or secure-cookie requirements are not satisfied.
