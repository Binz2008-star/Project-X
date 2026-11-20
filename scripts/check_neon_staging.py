"""Read-only verification of Project X's isolated Neon Staging schema.

Run with NEON_STAGING_DATABASE_URL in the process environment. Never copy
connection strings into source files, command line arguments or CI logs.
"""

from __future__ import annotations

import json
import os
import sys

from sqlalchemy import inspect, text
from sqlalchemy.engine import Engine, make_url

from project_x.server.db import engine_for

# This is branch-specific public endpoint metadata, NOT a credential. A changed
# Neon compute endpoint requires an intentional review and update here.
STAGING_HOST = "ep-crimson-cherry-bdz9jf81.c-8.us-east-2.aws.neon.tech"
EXPECTED_REVISION = "c8ad20261120"
EXPECTED_TABLES = frozenset({
    "alembic_version", "products", "users", "api_tokens", "devices",
    "licenses", "trials", "activation_codes", "license_events", "rate_buckets",
})
EXPECTED_INDEXES = frozenset({
    "ix_devices_user_product", "ix_licenses_product_status",
    "ix_licenses_user_expiry", "ix_activation_codes_product_status",
    "ix_events_license_time", "ix_events_type_time",
})
EXPECTED_UNIQUES = frozenset({
    "uq_license_user_product", "uq_trial_user_product", "uq_rate_bucket",
})


class StagingCheckError(RuntimeError):
    """Schema drift or unsafe Neon connection target."""


def verify_target(url: str) -> None:
    """Refuse a production or unknown endpoint; never log the connection URL."""
    parsed = make_url(url)
    if parsed.drivername != "postgresql+psycopg":
        raise StagingCheckError("Expected a postgresql+psycopg connection")
    if parsed.host != STAGING_HOST or parsed.database != "neondb":
        raise StagingCheckError("Database URL does not target Project X Neon staging")
    if parsed.query.get("sslmode") not in ("require", "verify-full"):
        raise StagingCheckError("A TLS-enforced sslmode is required")


def check_schema(engine: Engine) -> dict:
    """Read metadata and compare with the committed Alembic head, without writes."""
    inspector = inspect(engine)
    tables = set(inspector.get_table_names(schema="public" if engine.dialect.name == "postgresql" else None))
    missing = sorted(EXPECTED_TABLES - tables)
    if missing:
        raise StagingCheckError(f"Missing required tables: {', '.join(missing)}")

    with engine.connect() as connection:
        revision = connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one_or_none()
    if revision != EXPECTED_REVISION:
        raise StagingCheckError("Staging Alembic revision differs from the reviewed migration head")

    if "redemption_operation" not in {c["name"] for c in inspector.get_columns("activation_codes")}:
        raise StagingCheckError("Idempotent code-retry column is missing")
    indexes = set()
    uniques = set()
    foreign_keys = 0
    for table in EXPECTED_TABLES:
        indexes.update(x["name"] for x in inspector.get_indexes(table))
        uniques.update(x["name"] for x in inspector.get_unique_constraints(table) if x.get("name"))
        foreign_keys += len(inspector.get_foreign_keys(table))
    missing_indexes = EXPECTED_INDEXES - indexes
    missing_uniques = EXPECTED_UNIQUES - uniques
    if missing_indexes or missing_uniques or foreign_keys < 14:
        raise StagingCheckError(
            f"Schema constraints mismatch: missing indexes={sorted(missing_indexes)}, "
            f"missing uniques={sorted(missing_uniques)}, foreign_keys={foreign_keys}"
        )
    return {
        "status": "pass", "revision": revision, "table_count": len(EXPECTED_TABLES),
        "foreign_key_count": foreign_keys,
        "required_indexes_found": len(EXPECTED_INDEXES),
        "required_unique_constraints_found": len(EXPECTED_UNIQUES),
        "scope": "schema_read_only",
    }


def main() -> int:
    url = os.environ.get("NEON_STAGING_DATABASE_URL")
    if not url:
        print("NEON_STAGING_DATABASE_URL is required (supply via secrets manager)", file=sys.stderr)
        return 2
    try:
        verify_target(url)
        engine = engine_for(url)
        try:
            print(json.dumps(check_schema(engine), sort_keys=True))
        finally:
            engine.dispose()
    except Exception as error:
        # Never render arbitrary driver exceptions: they may include secrets.
        print(f"Staging verification failed ({type(error).__name__})", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
