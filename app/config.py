from __future__ import annotations
import os

VERSION = "1.2.5"
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./nexvary_vscan.db")
ADMIN_PASSWORD = os.getenv("NEXVARY_ADMIN_PASSWORD", "ChangeMe123!")
SESSION_SECRET = os.getenv("SESSION_SECRET", "local-dev-only-change-in-production")
MAX_PAGES = min(max(int(os.getenv("VSCAN_MAX_PAGES", "50")), 1), 200)
MAX_REQUESTS = min(max(int(os.getenv("VSCAN_MAX_REQUESTS", "120")), 10), 400)
REQUEST_DELAY = min(max(float(os.getenv("VSCAN_REQUEST_DELAY", "0.05")), 0.0), 2.0)
ALLOW_PRIVATE_TEST_TARGETS = os.getenv("VSCAN_ALLOW_PRIVATE_TEST_TARGETS", "0") == "1"
