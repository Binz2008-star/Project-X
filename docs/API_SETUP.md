# Local setup, API contract and deployment notes

This document describes the independently built licensing API. It does not install third-party apps, operate a signing service, or process payments. Only the **fictional, owned test application** `demo.owned` is used in automated tests. Real customer onboarding and external production deployment are out of scope pending the security and legal gates in `API_STATUS.md`.

## Local requirements

- Python 3.12+; SQLite for local development, PostgreSQL 16 recommended for production.
- No credentials or signing keys committed to Git.
- Run from repository root.

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-dev.txt
cp .env.example .env
# Replace CODE_PEPPER and TOKEN_PEPPER in .env with DIFFERENT strong secrets.
# Or inject values from a secure environment manager.
set -a; source .env; set +a
alembic upgrade head
python -m project_x.server.cli bootstrap-admin
uvicorn project_x.server.asgi:app --host 127.0.0.1 --port 8000
```

The bootstrap command prints an administrator bearer token **once**. Store it in your password manager or secrets vault. Never paste it into tickets, shell histories, source files, screenshots, or browser-based consoles. Use the token over a secure connection only.

Swagger UI: <http://127.0.0.1:8000/docs>; OpenAPI JSON: <http://127.0.0.1:8000/openapi.json>. Checked-in reproducible schema: [`openapi.json`](openapi.json). Protected endpoints require `Authorization: Bearer <token>`; the Swagger **Authorize** control supports HTTP Bearer.

## Authenticate, provision, and exercise a demo (local only)

1. Use your admin token against `POST /api/v1/admin/products` to create `demo.owned` with a *test-only*, traceable `rights_reference` (e.g. `owned-internal-test-app`), bundle ID such as `test.projectx.demo`, features `['theme', 'export']`, and `status: 'available'`. Never use an unlicensed proprietary product as a demo.
2. Admin creates the customer with `POST /api/v1/admin/users` (`account_identifier`) and receives `user_id`.
3. Admin issues that customer's token with `POST /api/v1/admin/tokens` (`user_id`) and stores it securely. This is test-only provisioning: production should use external identity verification.
4. Admin issues activation codes using `POST /api/v1/admin/codes/batch` with `product_id`, `duration_days` (30 or 90 by default), and `count` (1..100). Raw codes appear *once* in the response and are not persisted.
5. Customer calls `POST /api/v1/trials/start` with `product_id` for a seven-day trial, or `POST /api/v1/licenses/activate` with `product_id` and `activation_code`.
6. Customer calls `POST /api/v1/licenses/validate` with `license_id` and optionally `device_id`, and receives status, product, expiry, features and device-registration status. If `device_id` is omitted, status is `not_registered`. `POST /api/v1/devices/register` issues a server-assigned ID with status `unverified`, **not device attestation**.
7. Renew by `POST /api/v1/licenses/renew` with `license_id` and a new code. Customers can permanently revoke their own license at `POST /api/v1/licenses/revoke`. Admin equivalents live under `/api/v1/admin/`.

The client *cannot* select a user ID; identity comes from the bearer token. A revoked license can neither be activated again nor renewed. Device registration alone is not evidence of a trusted device. The subscription lifetime does **not** depend on iOS certificate expiry.

## PostgreSQL deployment preparation (NOT yet production approval)

Configure an isolated PostgreSQL database (TLS required in transit), e.g. `postgresql+psycopg://...` using a secrets manager rather than a committed URL. Restrict database credentials and service network access; set connection pooling and managed backups. Run migrations as a separate deployment job with a privileged migration role before starting application workers:

```bash
alembic upgrade head
uvicorn project_x.server.asgi:app --host 0.0.0.0 --port 8000
```

Only place the ASGI server behind a TLS-terminating ingress with WAF/IP rate limiting and an authentication boundary. `/health/live` and `/health/ready` support probes; do not expose raw database errors externally. Do not publish or deploy until `API_STATUS.md` security gates, PostgreSQL integration results, monitoring, backups and secret rotation have been reviewed and approved. This is **not** a go-live instruction.

## Tests

```bash
python -m pytest -q tests/test_api.py
python -m unittest discover -s tests -p 'test_licensing.py' -v
python -m scripts.export_openapi --check
```

The integration suite runs against isolated migrated SQLite schemas by default, and also against isolated PostgreSQL schemas when `PROJECT_X_TEST_POSTGRESQL_URL` is supplied. CI provisions PostgreSQL 16 and runs both backends. `alembic check` verifies no ORM/schema drift after upgrading. Changes to the model require a reviewed Alembic revision; **do not run create_all or manually patch production tables**.

## Important semantics

- Durations are exact **30/90-day periods** as requested, unlike the legacy local prototype's calendar months. Configurable via `LICENSE_DURATIONS_DAYS`; current active subscriptions extend from current expiry, expired from server now.
- Trials are unique per authenticated user and product, regardless of devices or reinstalls. User identification still requires a production-grade identity provider to prevent account farming.
- Code redemption changes code status and license in **one transaction** using `UPDATE ... WHERE status='issued' RETURNING`. A single code cannot be claimed twice; any subsequent error rolls it back.
- Product status `available` requires a nonempty rights reference entered by an admin, but that text alone does not prove commercial rights. This must be checked outside the service.
- The public repository contains no actual customer data, sample production credentials, third-party IPA or app signing material.
