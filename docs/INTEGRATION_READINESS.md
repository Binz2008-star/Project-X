# Analyzer-to-Build-Manager integration readiness

Status: **converged and locally verified with synthetic owned fixtures in the Draft PR #10 stack. No merge, deployment, signing, repackaging, injection, Neon change, or device action is included.** Exact head SHAs and GitHub Actions run IDs are recorded in the PR bodies and the final evidence report.

This stacked increment converges the read-only IPA analyzer from Draft PR #7 with the fail-closed Build Manager preflight from Draft PR #9. It proves that a real `IpaInspectionReport` produced from a synthetic, locally generated owned IPA satisfies the exact report contract consumed by the preflight gate.

## What this increment proves

- The analyzer's current `schema_version = "1.1"` report is passed directly to `project_x.buildmanager.evaluate()` without reshaping or hand-editing. Legacy `1.0` reports are also accepted; unknown schemas are rejected without echoing the value.
- The owner manifest derived from that report's identity and SHA-256 passes the gate. Appending bytes to the inspected archive changes its hash and breaks the binding.
- The resulting plan is still `mode = dry_run`, `execution_permitted = false`, `status = READY_FOR_INDEPENDENT_REVIEW`, with advisory-only authorization (`cryptographically_verified = false`).
- Analyzer finding codes emitted by realistic structural scenarios are in the preflight allowlist, including A7 codes; severities are recomputed from the allowlist and mismatches fail closed.
- Critical analyzer findings, stale hashes, wrong identity, forged/unsafe authorization, unexpected manifest fields, malformed reports, ambiguous roots and unsupported architectures block the plan.
- Analyzer warnings are retained in `plan.review_findings`, but finding details, contexts, archive paths and local paths are not copied into the result.
- The analyzer and preflight CLIs both accept/consume real synthetic reports without echoing private directories.

## What this increment does not prove

- No real third-party IPA is inspected, modified, or used as a build input.
- No signing validity, malware verdict, injection method, hook path, rpath relocation, installation, or device behaviour is established.
- No owner-owned buildable iOS application artifact is produced here. The `demo.owned` app is a synthetic ZIP/Mach-O fixture only.
- The manifest is an unsigned owner declaration, not a cryptographic signature. `authorization.py` is a separate fail-closed gate; even a verified permit is dry-run-only.
- The physical iPhone 13 milestone remains blocked by written scope, signing identity, provisioning profile, registered UDID, approved injection method, and verified hook path.

## Changed files

| File | Purpose |
| --- | --- |
| `project_x/ipa/` | Read-only analyzer modules converged from Draft PR #7, including A7 and independent re-review corrections. |
| `scripts/inspect_ipa.py` | Analyzer CLI with safe report publication. |
| `project_x/buildmanager/` | Preflight plus the separate fail-closed authorization gate from Draft PR #9. |
| `scripts/build_manager_preflight.py` | Bounded JSON CLI with fixed error codes. |
| `tests/test_ipa_analysis.py` | Analyzer tests with shared fixture builders. |
| `tests/ipa_fixtures.py` | Shared synthetic ZIP/Mach-O builders. |
| `tests/test_build_manager_preflight.py` | Preflight policy and input-bound tests. |
| `tests/test_build_manager_authorization.py` | Default-reject authorization-gate tests. |
| `tests/test_build_manager_integration.py` | Direct report-to-plan contract tests using real analyzer output. |
| `.github/workflows/ci.yml` | CI steps for analyzer, build manager, authorization, and integration tests. |
| `docs/IPA_ANALYSIS.md` | Analyzer architecture and review-closure notes. |
| `docs/IPA_BUILD_MANAGER.md` | Build Manager architecture and authorization boundary. |
| `docs/REVIEW_FINDINGS_MATRIX.md` | Full A7/B9/integration closure matrix and owner blockers. |
| `docs/INTEGRATION_READINESS.md` | This document. |

## Verification

Local Python 3.14.7 in the repository virtual environment (2026-11-21), with Windows `--basetemp` overrides:

- `pytest -q tests/test_ipa_analysis.py` → **74 passed, 1 skipped** (symlink test unavailable on this filesystem; Linux CI exercises it).
- `pytest -q tests/test_build_manager_preflight.py tests/test_build_manager_authorization.py` → **142 passed**.
- `pytest -q tests/test_build_manager_integration.py` → **18 passed**.
- Combined API, staging guard, analyzer, preflight, authorization and integration suites → **265 passed, 30 skipped**.
- `unittest discover -s tests -p test_licensing.py -v` → **OK (7 tests)**.
- `python -m scripts.export_openapi --check` → **OpenAPI schema matches implementation**.
- Isolated SQLite `alembic upgrade head` + `alembic check` → clean, no new upgrade operations.
- `git diff --check` → clean.

CI uses Python 3.12. Exact final-head run IDs and results are recorded in the PR bodies.

## Security and compatibility considerations

- The analyzer remains read-only: it opens the synthetic archive for reading only and never extracts or writes a bundle path from archive metadata.
- The preflight remains read-only and fail-closed. Unknown analyzer codes, false verification claims, malware verdicts, unresolved `@rpath` dependencies, invalid architecture/encryption state, and identity/hash drift are rejected.
- Compatibility is tested at the JSON contract boundary, not against a live host app. The instrumented third-party identity and exact version gate from the earlier core milestone are untouched.
- No secret, private path, signing material, provisioning-profile metadata, or device identifier is copied into the plan.

## Outstanding risks

1. Integration uses synthetic analyzer output only; a real owner-owned application artifact has not been inspected or recorded.
2. Signing identity, provisioning profile, registered UDID, and written device scope remain unavailable; all corresponding plan steps remain `blocked`.
3. No approved injection/implantation method or verified hook path exists.
4. The analyzer and preflight are in one stack, but no merge to `main` is requested.

## Independent review

PR #7 required one correction round after its first independent `REQUEST CHANGES` verdict; the final head awaits a fresh explicit `APPROVE`/`REQUEST CHANGES` verdict. PR #9 and PR #10 independent reviews are pending. No PR is merge-ready until each has an explicit approval on its final head.

## Next executable milestone

A local-only owned-app integration rehearsal: with an owner-provided, buildable iOS test application, generate a reproducible artifact manifest, inspect it with the analyzer, and drive the preflight CLI end to end. Signing, installation, third-party apps, and device QA remain out of scope until separately authorized.
