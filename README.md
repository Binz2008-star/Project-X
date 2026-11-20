# Project X — iOS Plus Product Lab

Independent technology project for **authorized** iOS app enhancements, feature licensing, build infrastructure, and eventual distribution. The first goal is one legally viable, supportable product, not a consumer storefront.

## Current handoffs (20 November 2026)

- [Project handoff — scope, verified status, PR chain and next decisions](docs/PROJECT_HANDOFF.md)
- [Engineering / operations handoff — architecture, Neon inventory, tests and safe next steps](docs/ENGINEERING_HANDOFF.md)

## Current implementation (phase 1, preserved)

- [Original local licensing prototype](project_x/licensing.py): one-use activation codes, 7-day trials, monthly/quarterly entitlements independent of app-signing validity.
- [Unit tests](tests/test_licensing.py) and GitHub Actions CI.
- [Engineering plan and upstream Swing assessment](docs/PHASE_1.md).
- [Rights and supplier register](docs/RIGHTS_REGISTER.md).
- [Prototype boundaries](docs/LICENSING.md).
- [API setup and local development](docs/API_SETUP.md), [implementation and security status](docs/API_STATUS.md), and [versioned OpenAPI spec](docs/openapi.json).

Run locally with Python 3.12+:

```bash
python -m unittest discover -s tests -v
```

**Not production-ready**: the API service is implemented in feature branches, but no verified customer authentication, device attestation, payments, app binaries, or live distribution exists. `approved` product entries require verified legal rights before real use. No third-party IPA, decrypted binary, tweak source, Apple certificate or signing secret is stored here. The public repository should not receive credentials or customer data.

Swing reference: <https://github.com/theoccurrence/Swing>. We have deliberately **not** copied Swing into this repo: its top-level commercial reuse rights have not been established, and its dependencies and the source iOS applications must each be cleared separately. No relationship with Instagram, YouTube, Snapchat or TikTok is claimed.

## Phase 2 — REST licensing API (separate draft branch)

Implemented under `project_x/server/` using FastAPI, SQLAlchemy and Alembic.
**New service is separate from the legacy SQLite LicenseStore**, which is kept for regression tests.

- [API setup and local deployment](docs/API_SETUP.md)
- [Full API contract (OpenAPI)](docs/openapi.json)
- [Implementation status and pending production gates](docs/API_STATUS.md)
- [Initial migration](migrations/versions/b85625159f44_initial_license_service_schema.py)
- [SQLite and PostgreSQL integration tests](tests/test_api.py)

No storefront, payment gateway, third-party IPA, commercial tweak source or signing keys.
This is an engineered prototype and **must not be exposed as a live commercial API until the pending security gates are closed**.

## Neon staging (isolated; not an API deployment)

- [Verified Neon staging database and guarded test procedure](docs/NEON_STAGING.md)
- Read-only schema preflight: `python -m scripts.check_neon_staging`
- Guarded staging API tests (requires staging-only secret URL): `python -m scripts.run_neon_staging_tests`

Staging connection credentials are **never** committed; staging and production are isolated Neon branches.
