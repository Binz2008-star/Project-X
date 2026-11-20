# Project X — Engineering / Operations Handoff

**Updated:** 20 November 2026  
**Source inspected:** [feature/neon-staging-readiness](https://github.com/Binz2008-star/Project-X/tree/feature/neon-staging-readiness), commit `5b2e48a3bb7912aef42467fcb2b1d4ca5d8df888`.  
**Companion:** [PROJECT_HANDOFF.md](PROJECT_HANDOFF.md). Read [API_STATUS.md](API_STATUS.md), [API_SETUP.md](API_SETUP.md), and [NEON_STAGING.md](NEON_STAGING.md) for detailed contracts/limitations.

## Git state / review chain

| Base | Head | Draft PR |
|---|---|---|
| `main` | `feature/phase-1-foundation` | [#1](https://github.com/Binz2008-star/Project-X/pull/1) |
| `feature/phase-1-foundation` | `feature/license-api-v1` | [#2](https://github.com/Binz2008-star/Project-X/pull/2) |
| `feature/license-api-v1` | `feature/license-idempotency-device-limits` | [#3](https://github.com/Binz2008-star/Project-X/pull/3) |
| `feature/license-idempotency-device-limits` | `feature/neon-staging-readiness` | [#4](https://github.com/Binz2008-star/Project-X/pull/4) |

These are proposed changes, **not merged**. Do not silently retarget or merge PRs; if approval is given, review their dependencies and recalculate diffs in order.

## Code ownership boundaries

- `project_x/licensing.py`: unchanged legacy SQLite-only experiment; kept for seven regression tests; **not** used by REST API.
- `project_x/server/api.py`: versioned FastAPI routes, authentication/authorization enforcement, basic DB-backed rate limits, HTTP error handling.
- `project_x/server/service.py`: license domain operations; atomic code claim/retry rules, trial/renewal/device quota enforcement and transactional audit records.
- `project_x/server/models.py`: product, user, license, activation code, trial, device, event, token and rate-bucket SQLAlchemy models.
- `project_x/server/schemas.py`: request/response validation. `security.py`: token/code hashing; `db.py`: connection/session setup; `config.py`: environment settings; `asgi.py`: ASGI app factory; `cli.py`: local admin bootstrap.
- `migrations/versions/b85625159f44_initial_license_service_schema.py` and `c8ad20261120_code_retry_operation.py`: Alembic history (apply new migrations, never use ORM `create_all()`).
- `tests/test_api.py`, `tests/test_licensing.py`, `tests/test_neon_staging_check.py`: integration, legacy regression, and guard tests. `scripts/export_openapi.py` checks [OpenAPI](openapi.json).
- `scripts/check_neon_staging.py`, `scripts/run_neon_staging_tests.py`: explicit host-pinned, TLS-checked Neon Staging inspection and HTTP test entry points. These do **not** deploy the API.

## Functional invariants to preserve

1. Product-agnostic license records keyed by authenticated customer user and product; no custom Instagram/Snapchat/YouTube/TikTok backend branches.
2. New products default to blocked and require separately documented rights; use only `demo.owned` for tests.
3. Trial: once per user/product, 7 days from server time. Subscriptions: 30 and 90 days; additional configured durations. Subscription expiration is independent from Apple app signing.
4. Active renewal extends the existing expiry; expired renewal starts at server time. Revoked license cannot be reactivated/renewed.
5. Activation codes are generated randomly, **stored as keyed cryptographic hashes**, one-use. Atomic database claim guards concurrent clients. **Same account + original operation + same code** retries return the existing license without additional extension or duplicate redemption events; cross-account or different-operation retries are rejected. Legacy redeemed codes without operation provenance intentionally fail closed.
6. Every successful code redemption creates a `code_redeemed` event and its related activation/renewal event in the same transaction. Admin product, license, user and token changes require audit. Raw codes and bearer credentials must never be written to event payloads.
7. Customer endpoints use identity bound to bearer token, admin-only endpoints require admin role, but **static bearer tokens are not verified customer login/OIDC** and cannot be assumed safe for public exposure.
8. Device registration enforces a per-user/product **inventory** cap, but each device is `unverified`. The API does not enforce device-attested access; no trustworthy device proof exists yet.

## API and local reproducibility

Required paths include `POST /api/v1/licenses/{activate,validate,renew,revoke}`, `POST /api/v1/trials/start`, `GET /api/v1/licenses/{license_id}`, `GET /api/v1/products`, and `/api/v1/admin/*` restricted endpoints. Consult checked-in [docs/openapi.json](openapi.json) rather than guessing JSON shapes.

For a **local-only** test checkout with Python 3.12+:

```sh
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-dev.txt
cp .env.example .env
# Supply distinct CODE_PEPPER and TOKEN_PEPPER through a private environment.
set -a; source .env; set +a
alembic upgrade head
python -m project_x.server.cli bootstrap-admin
uvicorn project_x.server.asgi:app --host 127.0.0.1 --port 8000
```

Swagger: `http://127.0.0.1:8000/docs`; machine-readable schema: `http://127.0.0.1:8000/openapi.json`. Never disclose the one-time printed admin token.

Run tests:

```sh
python -m pytest -q tests/test_api.py tests/test_neon_staging_check.py
python -m unittest discover -s tests -p 'test_licensing.py' -v
python -m scripts.export_openapi --check
```

The API tests use PostgreSQL when `PROJECT_X_TEST_POSTGRESQL_URL` is set. **Do not set this to production.** The secure Neon workflow has its own guard below.

## Neon inventory and safe staging procedure

| Item | Confirmed value |
|---|---|
| Neon project | `late-wind-49091088` (`Project X`), PostgreSQL 18, `aws-us-east-2` |
| Default production branch | `br-misty-haze-bdhh7kyw`; **0 app tables** at handoff |
| Non-default staging branch | `br-billowing-art-bd38um5w`; **ready** |
| Staging DB | `neondb` |
| Staging schema | 10 tables, 14 foreign keys, 7 unique constraints, 23 indexes |
| Staging Alembic revision | `c8ad20261120` |

Neon schema was applied from generated **committed Alembic SQL** on staging in one transaction; it was not run as online `alembic upgrade head` against Neon. All future schema changes must use reviewed Alembic revisions. **No live FastAPI-to-Neon connection has yet been demonstrated.**

A trusted operator should set `NEON_STAGING_DATABASE_URL` **only in a secure runtime**, using the direct staging endpoint and required TLS, then:

```sh
python -m scripts.check_neon_staging
python -m scripts.run_neon_staging_tests
```

The guard accepts only the explicitly pinned staging endpoint `ep-crimson-cherry-bdz9jf81.c-8.us-east-2.aws.neon.tech` with `postgresql+psycopg`, database `neondb` and TLS. Re-verify if Neon rotates that host. The integration runner creates/drops isolated PostgreSQL `test_...` schemas; interrupted runs may leave stale schemas needing investigation. Never paste or commit the full connection URL.

## Evidence / what is **not** tested

At [CI run #44645187179](https://github.com/Binz2008-star/Project-X/actions/runs/44645187179), on SHA `5b2e48a3bb7912aef42467fcb2b1d4ca5d8df888`:

- **58 passed** API integration tests across CI SQLite and CI PostgreSQL (1 test warning reported).
- **2 passed** offline staging-guard tests, **7 passed** legacy licensing tests.
- Alembic upgrade, drift check and PostgreSQL downgrade/re-upgrade; OpenAPI synchronization checks passed.
- Neon branch and table/revision state independently checked via read-only database access.

**Not tested:** API requests to live Neon Staging; customer identity from OIDC; Apple device attestation; account-level fraud resistance; production load/chaos; backup and recovery drills; staging API deployment; secret rotation; external security review; legally authorized iOS production binaries. CI passing does not mean production approval.

## Next engineer's acceptance gates

- [ ] Obtain staging URL via Neon console/secrets manager without exposing it and run the guarded schema preflight.
- [ ] Run and record actual authenticated FastAPI HTTP integration tests against temporary schemas on the live Neon staging branch.
- [ ] Review SQL transaction isolation / code and renewal concurrency under real connection pools.
- [ ] Add OIDC verified customer accounts and admin MFA/least-privilege roles; review bearer-token lifetime and revocation.
- [ ] Add server-verified device attestation and enforce product feature access per device; document privacy and anti-abuse limits.
- [ ] Validate logging redaction, secrets and backup/restore, WAF/IP throttling and environment separation.
- [ ] Obtain owner approval before any merge, external staging deployment or production change.

**Release gate remains CLOSED.** No storefront or payments in this workstream.
