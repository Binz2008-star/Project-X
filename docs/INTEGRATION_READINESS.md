# Analyzer-to-Build-Manager integration readiness

Status: **implemented and locally verified; Draft PR stack only. No merge, deployment,
signing, repackaging, injection, Neon change, or device action is included.**

This stacked increment converges the read-only IPA analyzer from Draft PR #7 with the
approved build-manager preflight from Draft PR #9. It proves that a real
`IpaInspectionReport` produced from a synthetic, locally generated owned IPA satisfies
the exact report contract consumed by the preflight gate.

## What this increment proves

- The analyzer's versioned `schema_version = "1.0"` report can be passed directly to
  `project_x.buildmanager.evaluate()` without reshaping or hand-editing.
- The owner manifest derived from that report's identity and SHA-256 passes the gate,
  and the resulting plan is still `mode = dry_run`, `execution_permitted = false`.
- Analyzer finding codes emitted by realistic structural scenarios are all present in
  the preflight allowlist.
- A critical analyzer finding, a stale artifact hash, or an unowned bundle identity
  blocks the plan using the real report payload.
- Analyzer warnings are retained in `plan.review_findings`, but finding details,
  contexts, archive paths, and local paths are not copied into the result.
- The CLI accepts a real analyzer report and manifest without echoing private paths.

## What this increment does not prove

- No real third-party IPA is inspected, modified, or used as a build input.
- No signing validity, malware verdict, injection method, hook path, rpath relocation,
  installation, or device behaviour is established.
- No owner-owned buildable iOS application artifact is produced here. The `demo.owned`
  app is a synthetic ZIP/Mach-O fixture only.
- The manifest is still an owner declaration, not a cryptographic signature; the report
  is trusted structurally after validation.

## Changed files

| File | Purpose |
| --- | --- |
| `project_x/ipa/` | Read-only analyzer modules converged from Draft PR #7. No behaviour change in this increment. |
| `scripts/inspect_ipa.py` | Analyzer CLI converged from Draft PR #7. |
| `docs/IPA_ANALYSIS.md` | Analyzer architecture and operating notes converged from Draft PR #7. |
| `tests/test_ipa_analysis.py` | Analyzer tests now import shared fixture builders. |
| `tests/ipa_fixtures.py` | New shared synthetic ZIP/Mach-O builders for analyzer and contract tests. |
| `tests/test_build_manager_integration.py` | New report-to-plan contract tests using real analyzer output. |
| `.github/workflows/ci.yml` | New CI step for the integration tests. |
| `docs/IPA_BUILD_MANAGER.md` | Links to this follow-up integration document. |
| `docs/INTEGRATION_READINESS.md` | This document. |

The approved preflight implementation itself is unchanged from PR #9 code head
`d9db3445c6ec5029456849e7ba0501ffcf2f7613`. PR #7 and PR #9 remain open drafts; this
increment does not merge or retarget them.

## Verification

Local, Python 3.14.7, repository virtual environment (2026-11-21):

- `pytest -q --basetemp <approved-temp> tests/test_build_manager_integration.py` → **7 passed**.
- `pytest -q --basetemp <approved-temp> tests/test_ipa_analysis.py` → **42 passed**.
- `pytest -q --basetemp <approved-temp> tests/test_build_manager_preflight.py` → **51 passed**.
- Combined API, staging guard, analyzer, preflight, and integration suites → **131 passed, 29 skipped**.
- `unittest discover -s tests -p test_licensing.py -v` → **OK (7 tests)**.
- `python -m scripts.export_openapi --check` → **OpenAPI schema matches implementation**.
- `git diff --check` → clean.

CI evidence will be recorded here after the first push and PR-level runs.

## Security and compatibility considerations

- The analyzer remains read-only: it opens the synthetic archive for reading only and
  never extracts or writes a bundle path from archive metadata.
- The preflight remains read-only and fail-closed. Unknown analyzer codes, false
  verification claims, malware verdicts, unresolved `@rpath` dependencies, invalid
  architecture/encryption state, and identity/hash drift are still rejected.
- Compatibility is tested at the JSON contract boundary, not against a live host app.
  The instrumented Instagram identity and exact version gate from PR #8 are untouched.
- No secret, private path, signing material, provisioning-profile metadata, or device
  identifier is copied into the plan.

## Outstanding risks

1. Integration uses synthetic analyzer output only; a real owner-owned application
   artifact has not been inspected or recorded.
2. Signing identity, provisioning profile, registered UDID, and written device scope
   remain unavailable; all corresponding plan steps remain `blocked`.
3. No approved injection/implantation method or verified hook path exists.
4. The analyzer and preflight are now in one stack, but no merge to `main` is requested.

## Independent review

Pending. Record the verdict here before treating the increment as review-complete.

## Next executable milestone

A local-only owned-app integration rehearsal: with an owner-provided, buildable iOS test
application, generate a reproducible artifact manifest, inspect it with the analyzer,
and drive the preflight CLI end to end. Signing, installation, third-party apps, and
device QA remain out of scope until separately authorized.
