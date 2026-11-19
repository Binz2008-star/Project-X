# Project X — Phase 1 execution and release gates

## Decision

Build one commercially authorized iOS feature pack, not a storefront or unauthorized rebrand of another company's iOS app. Instagram/Sparkle is a feasibility-research target only. We **cannot offer or distribute** a modified Instagram, Snapchat, YouTube, or TikTok binary without appropriate rights and a viable distribution channel. Stability of an old IPA is not a substitute for rights, security, or login compatibility.

## Four systems

1. **Build** — source provenance, pinned dependencies, reproducible builds, integrity checks, and signed artifacts once a legal test input is available.
2. **Features** — tweak inventory with owners, version support, licenses, and QA status per component.
3. **License** — independent feature entitlements, a 7-day trial, one-month and three-month codes. See the local prototype in project_x/licensing.py. Feature entitlement must not be confused with the validity of the installed iOS signature.
4. **Distribution** — a separately validated Apple-permitted channel and support for installation, revocation, and updates. Apple Enterprise internal distribution must not be repurposed as consumer resale.

## Swing research findings (inspected 2026-11-20)

- Upstream: <https://github.com/theoccurrence/Swing>, main SHA f16bf26e36102802692560274c8456ddbdf0ee6c.
- Generic Makefile/Theos build pipeline; app sets under apps/youtube and apps/instagram; Python tooling; local Node web UI and GitHub Actions automation.
- Requires a decrypted IPA source URL, external tweaks, compatible SDK/toolchain and separate signing/install arrangements.
- The observed upstream tree has no top-level LICENSE/COPYING. Obtain written reuse/commercial terms from its maintainer before copying or bundling code. Its git submodules require independent license analysis.
- Instagram set references efibalogh/sparkle-ig, licensed GPL-3.0. GPL permissions for that tweak do not confer rights to Instagram or its binaries.
- Swing's inspection hashes the **IPA URL string**, not the downloaded IPA bytes: Tools/inspect-ipa.py hashes args.source_url, and buildapp.yml validates the same URL digest. A production build requires trusted content SHA-256, provenance and tamper detection.
- Do **not** copy, vendor or distribute Swing or its third-party tweaks in Project X until source/asset rights are verified. The code in this repo is independently authored.

## Planning envelope, under USD 1,000

| Area | Tentative allowance | Exit condition |
|---|---:|---|
| Rights research and direct supplier outreach | $0–$150 | Signed terms |
| Local license prototype/tests | $0–$100 | Testable domain model |
| Qualified legal / technical advice | $0–$500 | Rights and channel cleared |
| Authorized iPhone proof of concept | $0–$250 | Licensed input and device tests |

Estimates, not supplier quotations or committed spending. Do not spend on a storefront before obtaining product rights.

## Release gates

- [ ] Written authorization to modify and redistribute the original application, or own and develop the original.
- [ ] Per-tweak rights, GPL/source-sharing obligations, maintenance responsibilities, security review.
- [ ] Valid distribution method for actual customer segment and regions.
- [ ] Reproducible build with byte-level SHA-256, pinned dependency inventory and signing-secret isolation.
- [ ] Actual iPhone tests: install, login, feature behavior, outage, revocation and update.
- [ ] Production license API: identity/authentication, rate limits, server time, retries/idempotency, audit trail, migrations, backups, privacy and fraud controls.
- [ ] Payments, refunds, consent, terms, trial notification and customer support.
- [ ] Independent legal and technical approval to charge a customer.

## Next iteration

1. Get permission and commercial offers directly from Swing and tweak maintainers and evaluate original-app redistribution rights independently.
2. Choose an owned/authorized product as the first target.
3. Expand the license domain model to an authenticated service behind a private operator console.
4. Connect a verified build adapter and conduct device QA. No production deployment or merge from this draft branch until review.
