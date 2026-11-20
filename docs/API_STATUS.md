# Licensing API Phase 2 — implementation and release gates

## Implemented in this branch

- Versioned FastAPI REST service, product-agnostic.
- Separate HTTP schemas, licensing service/domain operations, SQLAlchemy ORM models, database engine, and Alembic initial migration.
- Database URL configuration: SQLite for development, PostgreSQL (`psycopg`) for production target.
- Products, Users, Licenses, ActivationCodes, Trials, Devices, LicenseEvents; additional ApiTokens and shared RateBuckets.
- Strong server-generated activation codes, salted-by-secret HMAC-SHA256 digests, one-use transactional redemption.
- Per-user/product unique trials, seven-day trial, 30/90 days and configurable additional durations.
- Renewals stack on still-valid expiry or start at server time when expired. Revocation is permanent for a license record.
- Owner-isolated customer API, separate administrator-only API, admin token/customer token issuance and revocation, customer suspension, product blocking, history, device-change auditing.
- Shared per-token database-backed fixed-window rate limiting for activation, validation, and device registration; strict input validation.
- Server-issued device ID and status, deliberately `unverified` in the absence of trusted attestation.
- Regression tests of legacy LicenseStore plus SQLite/PostgreSQL HTTP integration tests in CI; versioned OpenAPI JSON, quickstart and security notes.

## NOT yet production-ready / pending

1. **Verified identity** — replace operator-issued static customer tokens with customer authentication (OIDC), customer enrollment proofs, secure refresh/revocation, MFA for admins and full role access policy. Tokens can be stolen from an untrusted modified app; do not ship them embedded in an IPA.
2. **Attestation and device policy** — register_device is a server-assigned ID, NOT device verification; implement Apple App Attest / suitable trust flow and abuse-resistant trial eligibility, with privacy review.
3. **Perimeter protections** — separate IP/network WAF limits, anomaly detection, DDoS controls, bucket TTL cleanup, durable monitoring and alerting. Shared DB counters are basic rate limits only.
4. **Operational resilience** — PostgreSQL load tests, outage handling, database migrations in staging and rollback strategy, backups, restore drills, secret rotation, token compromise playbook, transactional outbox for reliable external audit streams, retention/deletion policy.
5. **Secure production deployment** — no cloud deployment was performed. TLS, authentication boundary, logs/redaction, trace IDs, CI release controls and SAST/dependency scanning need staging validation.
6. **Semantics and UX** — explicit activation idempotency policy, account recovery, payments and refunds (out of current scope), trial notifications, legitimate rights evidence, actual authorized iPhone client QA.
7. **Rights/distribution** — proprietary app modification, commercial resale permissions and Apple-approved regional channels are not established. The sample application is fictional/owned for tests only; no third-party app can be sold based on this code.

## Compatibility and migration decision

`project_x/licensing.py` is kept as a legacy standalone SQLite prototype and retains its seven original tests; it is **not imported by the HTTP service** and should not be deployed. Its installation-ID-based trial and calendar-month licensing semantics intentionally differ from the new user-account-based 7/30/90-day API. Existing prototype `.db` files are **not automatically migrated** to the production schema. Plan a separate reconciled, idempotent data migration only if any real records exist and are authorized to transfer.

## Evidence policy

Test counts and CI outcome should be reported from the actual completed GitHub Actions run on this branch. Local SQLite test successes cannot establish PostgreSQL production or real-device security readiness. Do not merge or deploy without explicit owner approval.
