# Project X — Project Handoff

**Updated:** 21 November 2026

**Status:** engineering prototype; **NOT production-ready**  
**Scope:** this handoff summarizes the iOS Plus product direction and the current licensing-backend work. For implementation details, see [ENGINEERING_HANDOFF.md](ENGINEERING_HANDOFF.md). For authoritative implementation limitations, see [API_STATUS.md](API_STATUS.md), and for actual Neon facts, see [NEON_STAGING.md](NEON_STAGING.md).

## Current checkpoint (21 November 2026)

- `origin/main` is `0ecbe9c`, the reviewed iOS Core foundation ([PR #8](https://github.com/Binz2008-star/Project-X/pull/8)). No merge or deployment has been authorized for the newer draft chain.
- The current draft review chain is [PR #7](https://github.com/Binz2008-star/Project-X/pull/7) `46816c5` (read-only IPA analyzer), [PR #9](https://github.com/Binz2008-star/Project-X/pull/9) `705bcd9` (fail-closed Build Manager preflight), and [PR #10](https://github.com/Binz2008-star/Project-X/pull/10) `8c1ac3c` (analyzer-to-preflight integration). Independent final-head `APPROVE` verdicts are recorded in the PR evidence comments; all three remain **OPEN DRAFT**.
- [PR #11](https://github.com/Binz2008-star/Project-X/pull/11) `b7ba8d2` is a separate **OPEN DRAFT** for `feature/xinsta-static-integration`, based on `feature/integration-readiness` so its diff stays limited to the read-only IG456 static evidence and inert Xinsta Core diagnostics/settings work.
- Owner-directed hold: PRs #7/#9/#10 and any merge/readiness transition remain frozen until the single vertical-slice hook result is in. PR #11 is documentation/static-only and is not merge authorization.
- Runtime proof remains absent: no IPA execution, injection, signing, repackaging, installation, device test, or verified hook has been performed. See [IG456_STATIC_EVIDENCE.md](IG456_STATIC_EVIDENCE.md) and [XINSTA_CORE.md](XINSTA_CORE.md).

## Purpose and product boundary

Build an independent, expandable brand for **legally authorized** iOS enhancements with separately maintained systems for (A) app builds, (B) features/tweaks, (C) entitlements and activation, and (D) installation/distribution. A feature subscription **does not** extend or replace an expired iOS installation signature. Begin with **one owned/authorized sample product**, then prove licensing, repeatability and supportability before considering a storefront.

Instagram, Snapchat, YouTube and TikTok may be separate product records in the same licensing service, but **no rights to modify or redistribute these companies' original iOS apps have been established**. No third-party IPA, signing assets, or tweaked proprietary binary is included here. [Swing assessment](PHASE_1.md) and [rights register](RIGHTS_REGISTER.md) are research, not commercial permission.

**Out of scope:** storefront, checkout/payment integration, public IPA distribution, live consumer onboarding, commercial launch.

## Delivered (draft branches; not merged)

| Stage | Work delivered | Review |
|---|---|---|
| 1 — foundation | Local SQLite licensing prototype, basic 7-day trial, one-use codes, rights assessment; original seven regression tests retained | [PR #1](https://github.com/Binz2008-star/Project-X/pull/1) |
| 2 — service | Product-agnostic FastAPI REST under `/api/v1/`, SQLAlchemy models, Alembic, admin/customer bearer tokens, role checks, OpenAPI, SQLite/PostgreSQL CI | [PR #2](https://github.com/Binz2008-star/Project-X/pull/2) |
| 3 — correctness | Same-account/same-operation activation and renewal retry idempotency; atomic redemption, concurrent renewals, device-registration quota locking and event history | [PR #3](https://github.com/Binz2008-star/Project-X/pull/3) |
| 4 — staging | Neon PostgreSQL 18 `staging` branch, applied committed Alembic schema, checked constraints, guarded staging verification tooling; **no deployed service** | [PR #4](https://github.com/Binz2008-star/Project-X/pull/4) |

These four were the original **draft and stacked** licensing PRs: `main` ← phase 1 ← phase 2 ← phase 3 ← Neon staging readiness. That chain is historical; `origin/main` has since advanced to `0ecbe9c` with the reviewed iOS Core foundation, while the newer draft chain is listed in the checkpoint above. Do not mistake feature-branch code for production-deployed code. **Do not merge, deploy, or publish without explicit owner authorization.**

The documentation handoff is proposed in a separate branch/PR; it does not authorize any merge.

## Verified evidence at handoff

- [GitHub Actions run 44645187179](https://github.com/Binz2008-star/Project-X/actions/runs/44645187179) passed on feature/neon-staging-readiness commit `5b2e48a3bb7912aef42467fcb2b1d4ca5d8df888`: 58 API tests using CI SQLite and CI PostgreSQL, 2 local/offline Neon-target guard tests, 7 legacy unit tests, Alembic upgrade/check/downgrade/upgrade, and OpenAPI drift check.
- Neon project `Project X` (`late-wind-49091088`), PostgreSQL 18, `aws-us-east-2`. On 20 November 2026, read-only checks confirmed non-default `staging` branch `br-billowing-art-bd38um5w` with 10 tables and `alembic_version=c8ad20261120`. `production` branch `br-misty-haze-bdhh7kyw` still had **zero application tables**.
- The staging schema was created from committed Alembic upgrade SQL **using a Neon transaction**, not by connecting the backend to Neon and running its online Alembic CLI. No customer records, real accounts, or commercial code sales have been established.
- **Not verified:** authenticated HTTP requests against the live Neon Staging database; staging app deployment; iPhone device attestation; commercial app rights; external security assessment.

## Immediate next gate (ordered)

1. A trusted operator stores the **staging-only** direct PostgreSQL connection URL in a secure secrets store. Never place credentials in Git, a ticket, logs or a chat message.
2. Run `python -m scripts.check_neon_staging` with a secrets-managed `NEON_STAGING_DATABASE_URL`; confirm host, TLS, schema revision and indexes against the existing staging branch.
3. Run `python -m scripts.run_neon_staging_tests`. The runner is guarded against production and uses isolated temporary PostgreSQL test schemas; inspect failures, orphaned test schemas and sensitive logging before proceeding.
4. Conduct security review: verified customer authentication/OIDC, admin MFA and finer authorization, genuine device trust and per-device entitlement enforcement, abuse-resistant trials, network/WAF limits, secret rotation, audit/monitoring, backup/restore and incident response.
5. Only after explicit approval: consider a separate, private Staging API deployment and realistic device tests. Production is blocked until security/legal checks are signed off.

## Release blockers and risks

- **Identity:** customer tokens are currently operator-issued bearer tokens, not independently verified identities.
- **Device trust:** IDs issued by the server are currently `unverified`; device quotas do not enforce device-bound access.
- **Operational:** no actual cloud-hosted API or tested failure/recovery drills; deployment secrets are not configured by the current GitHub connector.
- **Commercial/legal:** Swing and third-party tweak/app modification/distribution rights and Apple-permitted distribution paths remain unresolved.
- **Public repository:** `Project-X` is presently public. Avoid uploading credentials, customer data, signing keys, vendor-private terms, proprietary tweak source or other private assets.

## Decision and change controls

Keep the original `project_x/licensing.py` for compatibility/regression, but do not deploy it as the new API. Keep product-agnostic features keyed by product ID, use the owned `demo.owned` test record for tests, avoid unnecessary dependencies and keep the current scope focused on licensing. Any merge of stacked PRs, database change to `production`, exposure to the internet, commercial app distribution, or release requires explicit owner approval.

**Next engineering owner:** continue at [ENGINEERING_HANDOFF.md](ENGINEERING_HANDOFF.md). This document is a checkpoint, not a claim of production readiness.
