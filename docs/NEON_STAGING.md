# Project X — Neon Staging (20 November 2026)

**Scope:** a separate, non-production Neon PostgreSQL database branch. This does not deploy the FastAPI backend or approve commercial use of any third-party app. All staging runs must use synthetic test accounts and the fictional test product `demo.owned` only.

## Verified inventory

| Item | Value |
|---|---|
| Neon project | `Project X` / `late-wind-49091088` |
| Staging branch | `staging` / `br-billowing-art-bd38um5w` |
| Parent branch | `production` / `br-misty-haze-bdhh7kyw` |
| Staging endpoint | `ep-crimson-cherry-bdz9jf81.c-8.us-east-2.aws.neon.tech` |
| Database | `neondb` |
| PostgreSQL | Version 18 |
| Region | `aws-us-east-2` |
| Current Alembic head | `c8ad20261120` |
| Initial schema migration | `b85625159f44` |

On 2026-11-20, the **existing committed Alembic revisions** were rendered to PostgreSQL SQL using `alembic upgrade head --sql`. Those generated statements were applied as a **single transaction to staging only** using the Neon database tool, including the `alembic_version` updates. They were not manually redesigned. This is equivalent SQL to the Alembic upgrade, but was **not** an online `alembic upgrade head` invocation. Always use the normal Alembic CLI for subsequent connected migrations.

Read-only verification after migration:

- 10 tables: `products`, `users`, `api_tokens`, `devices`, `licenses`, `trials`, `activation_codes`, `license_events`, `rate_buckets`, `alembic_version`.
- 14 foreign keys, 7 unique constraints and 23 indexes (including primary keys).
- `activation_codes.redemption_operation` present and the version table contains `c8ad20261120`.
- 0 customer users, 0 licenses, 0 activation codes at verification time. No production or real customer data copied.
- The production branch was **not** migrated or modified.

## Connecting safely

1. In the Neon dashboard for **Project X**, explicitly choose branch **`staging`**. Select the **direct** database connection (not the pooler) for Alembic migrations.
2. Obtain the staging branch's connection URL in the Neon dashboard. Change the protocol prefix to `postgresql+psycopg://` for SQLAlchemy/psycopg 3, keeping the remaining connection values intact; require `sslmode=require` or `sslmode=verify-full`.
3. Inject the URL as **`NEON_STAGING_DATABASE_URL`** from a secrets manager into the **local test process or secure CI secret**. Do not place the value in the GitHub repository, `.env.example`, workflow YAML, shell history, tickets, or logs.
4. This repository pins the known staging endpoint in `scripts/check_neon_staging.py`: the check **fails closed** if the connection points at the production endpoint, another Neon endpoint, SQLite, or a non-TLS URL. Review and update this guard only if Neon intentionally replaces the staging compute endpoint.
5. For a read-only schema and migration check:

   ```bash
   python -m scripts.check_neon_staging
   ```

6. For HTTP integration tests against a **temporary isolated schema** on the staging branch:

   ```bash
   python -m scripts.run_neon_staging_tests
   ```

   This guarded runner first checks that the target is the known staging endpoint and schema version. The existing `tests/test_api.py` fixture creates a unique `test_<random>` schema for every PostgreSQL test, runs Alembic and authenticated FastAPI HTTP tests, then drops that test schema in cleanup. It does not use the `public` schema for test records. These tests require `requirements-dev.txt` and SQL `CREATE SCHEMA` rights on staging. If a test process is forcibly terminated, a temporary `test_...` schema may remain and should be investigated before manual cleanup. Do not run raw unguarded integration tests against production.

## What is implemented vs. pending

**Implemented:** Staging branch created and isolated; migration SQL from committed Alembic scripts applied; tables and constraints verified; code and local guard/tests in the repository.

**Not yet performed:** connection of an always-on FastAPI service; live API HTTP calls to Neon; secret creation in GitHub (connector does not support writing repository secrets); authenticated customer onboarding; app attestation; production deployment; backups/restore drills and independent security review.

**Next gate:** A trusted operator adds the staging connection URL to a secure test runtime, runs the guarded API suite, reviews connection authorization/TLS, and signs off before any staging API deployment. Never merge or deploy automatically.

## Final read-only verification — 21 November 2026

At code head `3c38ca96116acf4e689a9519e554ab4b8ff899a0`, the environment did not
contain `NEON_STAGING_DATABASE_URL`. Both guarded scripts were run and failed
closed without database access: `python -m scripts.check_neon_staging` exited 1
with `NEON_STAGING_DATABASE_URL is required`, and
`python -m scripts.run_neon_staging_tests` exited 1 with
`Missing NEON_STAGING_DATABASE_URL`. No unrelated local configuration file was
used as a credential source. Therefore **live guarded connection and live HTTP
integration remain `BLOCKED`**, not failed tests and not a PostgreSQL pass.

Read-only authorized Neon tooling confirmed:

- project `late-wind-49091088`, staging branch `br-billowing-art-bd38um5w`, and
  direct staging compute host `ep-crimson-cherry-bdz9jf81`;
- production compute is distinct (`ep-falling-bird-bdgbs39b`) and was not read
  for data or modified;
- `public.alembic_version` is `c8ad20261120`, matching the committed head;
- 10 expected `public` tables are present;
- `users`, `licenses`, `activation_codes`, and `products` counts were all zero;
- three leftover schemas still exist: `test_419ef9234d58e644`,
  `test_71052392b993781a`, and `test_eabedc40e0a21b1a`. They were neither
  cleaned nor modified; cleanup requires separate approval.

CI at the same code head (`44912738704`) passed the offline Neon staging guard
(`2 passed`) and local/ephemeral PostgreSQL migration checks, but CI did not
contact Neon and skipped PostgreSQL API cases are not evidence of live staging
integration. Required next access: a securely supplied direct staging URL with
TLS and permission for isolated `test_*` schemas only; then run the two guarded
scripts and verify schema cleanup.
