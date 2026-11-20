"""Run integration tests against *only* the verified Project X Neon staging endpoint.

The pytest fixture creates and drops isolated test_... schemas, NOT the public
schema. This helper prevents accidentally testing the production endpoint.
"""

from __future__ import annotations

import os
import subprocess
import sys

from project_x.server.db import engine_for
from scripts.check_neon_staging import StagingCheckError, check_schema, verify_target


def main() -> int:
    url = os.environ.get("NEON_STAGING_DATABASE_URL")
    if not url:
        print("Missing NEON_STAGING_DATABASE_URL", file=sys.stderr)
        return 2
    try:
        verify_target(url)
        engine = engine_for(url)
        try:
            check_schema(engine)
        finally:
            engine.dispose()
    except Exception as error:
        # Avoid printing third-party DB errors containing a connection URI.
        print(f"Staging safety preflight failed ({type(error).__name__})", file=sys.stderr)
        return 1
    env = os.environ.copy()
    env["PROJECT_X_TEST_POSTGRESQL_URL"] = url
    # Pytest's fixture uses temporary per-test schemas and drops them after use.
    return subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "tests/test_api.py"], env=env, check=False,
    ).returncode


if __name__ == "__main__":
    raise SystemExit(main())
