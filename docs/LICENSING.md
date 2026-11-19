# Local-only license prototype: scope and limitations

The Python standard-library module project_x/licensing.py is an isolated demonstration, **not** an internet-facing API and **not** a payment or Apple-signing system. Its intended behavior:

- register_product(product_id, rights_status="blocked"): all new products fail closed by default. "approved" is an offline operator flag, not proof of authorization.
- start_trial(product_id, installation_id): grants 7 days at most once per product/installation identifier.
- issue_code(product_id, plan): issues a high-entropy single-use code for monthly or quarterly plans, stores its SHA-256 digest, returns the plaintext code only once.
- redeem(code, installation_id): transactional one-use redemption, calendar-month expiry; stacking extends an existing active grant.
- entitlement(product_id, installation_id): validates expiry and that the product remains marked approved.

Installation IDs are **self-declared and forgeable**. Clearing the app or rotating IDs can enable another trial. This is not a fraud-resistant commercial deployment. API authentication, operator permission checks, signed app requests, account/device identity, rate limits, revocation, billing and payment integration, audits, backups, migration management, privacy notices and production key management remain unimplemented. No personal data should be put in this public repository.

## Run unit tests

\`\`\`bash
python -m unittest discover -s tests -v
\`\`\`

## Local demonstration only

\`\`\`python
from project_x import LicenseStore

store = LicenseStore("local-demo.db")
store.register_product("demo.featurepack", "approved")  # ONLY a mock product
trial_end = store.start_trial("demo.featurepack", "test-install-001")
code = store.issue_code("demo.featurepack", "monthly")
sub_end = store.redeem(code, "test-install-001")
print(trial_end, sub_end)
print(store.entitlement("demo.featurepack", "test-install-001"))
\`\`\`

A launch service must bind entitlements to authenticated customer accounts and an abuse-resistant, privacy-reviewed device association design, and keep feature subscriptions separate from iOS signing/installation rights.
