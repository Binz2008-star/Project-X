# Licensing API Phase 2 — implementation and release gates

## Implemented in this branch

- Versioned FastAPI REST service, product-agnostic.
- Separate HTTP schemas, licensing service/domain operations, SQLAlchemy ORM models, database engine, and Alembic initial migration.
- Database URL configuration: SQLite for development, PostgreSQL (`psycopg`) for production target.
- Products, Users, Licenses, ActivationCodes, Trials, Devices, LicenseEvents; additional ApiTokens and shared RateBuckets.
- Strong server-generated activation codes, keyed HMAC-SHA256 digests, one-use transactional redemption.
- Account-scoped idempotent activation/renewal retries using the same redeemed code and operation; no double expiry extension, duplicate redemption event, or cross-account reuse. Previously redeemed codes lack operation provenance and intentionally cannot be replayed.
- One additional Alembic revision records redemption operation and is reversible; existing tables and local legacy LicenseStore remain intact.
- Per-user/product unique trials, seven-day trial, 30/90 days and configurable additional durations.
- Renewals stack on still-valid expiry or start at server time when expired. Revocation is permanent for a license record.
- Owner-isolated customer API, separate administrator-only API, admin token/customer token issuance and revocation, customer suspension, product blocking, history, device-change auditing.
- Shared per-token database-backed fixed-window rate limiting for activation, validation, and device registration; strict input validation.
- Server-issued device ID and status, deliberately `unverified` in the absence of trusted attestation. Configurable per-account/per-product registration cap with PostgreSQL account-row locks and SQLite reserved-write transaction; revoking a device releases a slot. Device attestation and per-device feature enforcement are NOT implemented.
- Regression tests of legacy LicenseStore plus SQLite/PostgreSQL HTTP integration tests in CI; versioned OpenAPI JSON, quickstart and security notes.

## NOT yet production-ready / pending

1. **Verified identity** — replace operator-issued static customer tokens with customer authentication (OIDC), customer enrollment proofs, secure refresh/revocation, MFA for admins and full role access policy. Tokens can be stolen from an untrusted modified app; do not ship them embedded in an IPA.
2. **Attestation and device policy** — register_device is a server-assigned ID, NOT device verification; implement Apple App Attest / suitable trust flow and abuse-resistant trial eligibility, with privacy review.
3. **Perimeter protections** — separate IP/network WAF limits, anomaly detection, DDoS controls, bucket TTL cleanup, durable monitoring and alerting. Shared DB counters are basic rate limits only.
4. **Operational resilience** — PostgreSQL load tests, outage handling, database migrations in staging and rollback strategy, backups, restore drills, secret rotation, token compromise playbook, transactional outbox for reliable external audit streams, retention/deletion policy.
5. **Secure production deployment** — no cloud deployment was performed. TLS, authentication boundary, logs/redaction, trace IDs, CI release controls and SAST/dependency scanning need staging validation.
6. **Semantics and UX** — idempotent same-code retry is implemented, but a later license renewal can change the returned license snapshot; caller must fetch current state when needed. Account recovery, trial notifications, legitimate rights evidence and actual authorized iPhone client QA remain pending. Payments and refunds are out of scope.
7. **Rights/distribution** — proprietary app modification, commercial resale permissions and Apple-approved regional channels are not established. The sample application is fictional/owned for tests only; no third-party app can be sold based on this code.

## Compatibility and migration decision

`project_x/licensing.py` is kept as a legacy standalone SQLite prototype and retains its seven original tests; it is **not imported by the HTTP service** and should not be deployed. Its installation-ID-based trial and calendar-month licensing semantics intentionally differ from the new user-account-based 7/30/90-day API. Existing prototype `.db` files are **not automatically migrated** to the production schema. Plan a separate reconciled, idempotent data migration only if any real records exist and are authorized to transfer.

## Evidence policy

Test counts and CI outcome should be reported from the actual completed GitHub Actions run on this branch. Local SQLite test successes cannot establish PostgreSQL production or real-device security readiness. Do not merge or deploy without explicit owner approval.

## Follow-on hardening review — 2026-11-20

**Implemented in feature/license-idempotency-device-limits:**

- Atomic `UPDATE ... WHERE status='issued' RETURNING`, with replay allowed only when the same authenticated user re-sends the same code for the same original operation and license. Revoked licenses remain invalid. New code redemption writes exactly one `code_redeemed` event plus one activation or renewal event in the same transaction; responses never expose the raw secret.
- PostgreSQL row lock prevents lost renewal extensions and serializes device registrations per account. SQLite performs `BEGIN IMMEDIATE` on relevant writes, including trials and revocations. Configurable `MAX_DEVICES_PER_PRODUCT` defaults to 5.
- CI tests cover retries, cross-account replay rejection, operation replay rejection, dual-code concurrent renewal, single-code concurrent retry, device cap, device-slot reuse, and audit redaction.
- Alembic adds nullable `redemption_operation` to activation codes. Existing records with unknown operation remain nonreplayable rather than being incorrectly treated as valid retries. Downgrade drops this new field; a production downgrade would remove idempotency metadata, so it must be planned carefully.

**Security sign-off: NOT GRANTED.** Customer tokens are admin-issued static bearer credentials, not verified customer identity; device records remain unverified and the entitlement API may return account features even without a device ID. Therefore the device registration cap is an inventory cap, **not enforceable device-bound access control**. Do not make commercial or public deployment claims. Pending: OIDC or account verification, Apple attestation, per-device policy enforcement, MFA and finer RBAC for admins, secret rotation, network throttling, TLS/WAF, structured audit export, load testing, backup/restore drills, database isolation and privacy review.
