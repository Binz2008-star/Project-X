# Project X — iOS Plus Product Lab

Independent technology project for **authorized** iOS app enhancements, feature licensing, build infrastructure, and eventual distribution. The first goal is one legally viable, supportable product, not a consumer storefront.

## Current implementation (phase 1)

- [Original local licensing prototype](project_x/licensing.py): one-use activation codes, 7-day trials, monthly/quarterly entitlements independent of app-signing validity.
- [Unit tests](tests/test_licensing.py) and GitHub Actions CI.
- [Engineering plan and upstream Swing assessment](docs/PHASE_1.md).
- [Rights and supplier register](docs/RIGHTS_REGISTER.md).
- [Prototype boundaries](docs/LICENSING.md).

Run locally with Python 3.12+:

\`\`\`bash
python -m unittest discover -s tests -v
\`\`\`

**Not production-ready**: no public API, payments, app binaries, device-validated trials or live distribution. Product entries marked approved require verified legal rights before real use. No third-party IPA, decrypted binary, tweak source, Apple certificate or signing secret is stored here. The public repository should not receive credentials or customer data.

Swing reference: <https://github.com/theoccurrence/Swing>. We have deliberately **not** copied Swing into this repo: its top-level commercial reuse rights have not been established, and its dependencies and the source iOS applications must each be cleared separately. No relationship with Instagram, YouTube, Snapchat or TikTok is claimed.
