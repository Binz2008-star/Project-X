# Project X — project instructions for OpenCode

## Identity and objective

This repository is **Project X**, an independent, product-agnostic licensing backend and future distribution/business infrastructure for **authorized** enhanced iOS applications. The first deliverable is a reliable, safely testable license API for a sample application we own. This is **not** a storefront or payment project.

**Read before planning or changing code:**
1. `docs/PROJECT_HANDOFF.md` — latest project status, scope, risks and decisions.
2. `docs/ENGINEERING_HANDOFF.md` — architecture, branch chain, test evidence and operating procedures.
3. `docs/API_STATUS.md` — implemented features and security/release blockers.
4. `docs/NEON_STAGING.md` — actual Neon staging schema and protected test procedure.
5. `docs/API_SETUP.md` — local development and OpenAPI.

These documents describe a historical checkpoint, not necessarily the current Git/Neon state. Always check `git status -sb`, `git branch -vv`, `git remote -v`, local code, actual test output, and CI status before claiming completion.

## Current architecture and files

- Python 3.12+; FastAPI `/api/v1/`; SQLAlchemy ORM; Alembic migrations; PostgreSQL (Neon staging) and local SQLite.
- `project_x/server/api.py`: HTTP routes, authentication/authorization, validation and rate limits.
- `project_x/server/service.py`: licensing business operations and transactional behavior.
- `project_x/server/models.py`: database entities; `schemas.py`: API contracts.
- `project_x/server/security.py`, `config.py`, `db.py`: secrets, configuration and persistence.
- `migrations/versions/`: the only approved way to evolve database schemas. Do not use ORM `create_all()` for application migrations.
- `tests/test_api.py` (API integration), `tests/test_licensing.py` (legacy), `tests/test_neon_staging_check.py` (connection safety).
- `docs/openapi.json`: generated API description. Use `python -m scripts.export_openapi --check` to check synchronization.
- `project_x/licensing.py`: legacy local SQLite prototype kept for regression; not the production API, do not remove casually.

## Branch and change safety

- **Main does not contain the new licensing service.** Implementation is on stacked draft PRs #1–#5, culminating in `docs/2026-11-20-handoffs`. This OpenCode onboarding branch is based on that stack. Confirm remote state instead of assuming merges.
- Do **not** merge, retarget or close PRs, push to `main`, deploy software, edit cloud production, delete or expose data, create paid resources or contact external parties without explicit owner authorization.
- Prefer a small new `feature/*` or `fix/*` branch from the current reviewed development branch; avoid force pushes and overwriting uncommitted local work.
- The repository is public. **Never** commit or print credentials, database URLs with passwords, API tokens, signing keys, private customer records or proprietary IPA/tweak binaries. Keep `.env` untracked; use secret injection.
- Never run `alembic upgrade`, raw migrations, integration tests or cleanup against Neon `production`. Do not run remote Neon staging writes without an explicit approved test scope. For staging use only documented host-guarded scripts and a secrets-managed `NEON_STAGING_DATABASE_URL`.
- No unlicensed Instagram/Snapchat/YouTube/TikTok IPA modifications or redistribution. Tests use the fictional/owned `demo.owned` product only.

## Invariants for licensing changes

- License belongs to an authenticated customer account and a product, not merely an installation string.
- 7-day trial per user/product; server-clock 30/90-day subscription terms and configurable durations; app-signing expiry independent of license expiry.
- Activation codes are one-use, stored only as keyed hashes, redeemed atomically. Idempotent retries are allowed only for the original authenticated user and original operation; no duplicate extensions.
- Active renewals extend from current expiration; expired renewals from current server time; revoked licenses remain invalid.
- Audit security-relevant events without secrets; admin capabilities are separate from customer endpoints.
- Current device registration is **unverified** and must not be marketed as Apple device attestation. Static bearer customer tokens are not verified OIDC identities; security review remains open.
- Separate routes, business rules, schema models and persistence. No storefront, payment gateway or deployment until approved.

## Verification workflow

Use local isolated SQLite by default; CI supplies an isolated PostgreSQL service.

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/test_api.py tests/test_neon_staging_check.py
.\.venv\Scripts\python.exe -m unittest discover -s tests -p test_licensing.py -v
.\.venv\Scripts\python.exe -m scripts.export_openapi --check
```

For migrations test against dedicated *local or ephemeral* databases, never against production. Record command output and failures; tests which skip PostgreSQL are not a PostgreSQL pass. Never claim remote tests, deployment, file edits, merges or device QA without direct evidence.

## First session instruction

Verify that the working directory is inside the `Project-X` Git repository, read the handoffs and code, inspect current branch and clean/dirty state, and produce a short status report. **Do not modify code until the user assigns the next engineering task.** Explain what is ready, what is unverified and the smallest safe next step.
