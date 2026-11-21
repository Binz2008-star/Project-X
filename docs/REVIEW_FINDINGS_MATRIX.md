# Review findings matrix — A7 / B9 / integration

Status values: **FIXED** (code, regression test and local verification present), **OPEN** (work in progress), **BLOCKED** (requires owner action or external prerequisite). Draft PRs are not merged.

## PR #7 — IPA Analyzer (A7)

| ID | Status | Fix | Regression evidence |
| --- | --- | --- | --- |
| A7-1 | FIXED | Single descriptor for parsing, raw-name validation, entry reads and SHA-256; `ARCHIVE_CHANGED_DURING_ANALYSIS` on descriptor change. | `tests/test_ipa_analysis.py` single-descriptor and descriptor-change tests. |
| A7-2 | FIXED | All top-level `Payload/*.app/` roots are detected even without `Info.plist`; `AmbiguousAppRootError` / CLI `AMBIGUOUS_APPLICATION_ROOT`. | Ambiguous-root, root-without-plist and nested-app counter-tests. |
| A7-3 | FIXED | Main and nested `Info.plist` identity values are typed/shape checked; CLI `INVALID_INFO_PLIST_VALUE`. | Parametrised main/nested malformed-value tests plus CLI mappings. |
| A7-4 | FIXED | `PROVISIONING_PROFILE_UNREADABLE` warning with fixed reasons only; no parser text. | Unreadable-profile regression test. |
| A7-5 | FIXED | Accurate signing field names; metadata-presence semantics; schema `1.1`. | Signing-field assertions and docs. |
| A7-6 | FIXED | Input descriptor identity captured and rechecked; no-overwrite link publication refuses a target recreated as the input. | Input-collision, hard-link, symlink and publication-race tests. |
| A7-7 | FIXED | Typed dependency refs; weak unresolved refs are warnings; arm64 subtype `1` normalised. | Weak/required split tests and real-byte subtype tests. |
| A7-8 | FIXED | Documentation no longer treats the private reference check as CI evidence or a compatibility claim. | `docs/IPA_ANALYSIS.md`. |
| A7-9 | FIXED | `origin/main` `0ecbe9c` merged without force; fresh CI green on each final head. | GH Actions runs `44840341459`, `44840347797`, `44841414033`, `44841419556`. |
| A7-R1 | FIXED | Independent re-review finding: nested plist values now use the same typed validation and cannot emit non-string fields or crash the CLI. | Parametrised nested-plist tests and CLI mapping. |
| A7-R2 | FIXED | Independent re-review finding: root detection no longer depends on a readable nested plist. | Root-without-plist inspection and CLI tests. |
| A7-R3 | FIXED | Independent re-review finding: publication race can no longer overwrite the archive with report bytes. | Monkeypatched publication-race test; static symlink test retained. |

## PR #9 — Build Manager (B9)

| ID | Status | Fix | Regression evidence |
| --- | --- | --- | --- |
| B9-1 | FIXED | Advisory declaration explicitly labelled; plan records `advisory_declaration_only` and `cryptographically_verified: false`. | Preflight plan assertions and docs. |
| B9-2 | FIXED | Separate fail-closed `authorization.py` permit gate; unsigned/forged input rejected; valid permit remains dry-run-only. | `tests/test_build_manager_authorization.py`, now in CI. |
| B9-3 | FIXED | No duplicated analyzer/IPA tests; analyzer-to-preflight tests remain only in PR #10. | Diff inspection and PR file lists. |
| B9-4 | FIXED | Bounded, output-safe identity validation with fixed `UNSAFE_IDENTITY_STRING` and no echo. | Preflight and integration rejection tests. |
| B9-5 | FIXED | arm64/arm64e, `arm64v8` and subtype `1` normalization; unsupported architectures blocked. | Preflight and real-report architecture tests. |
| B9-6 | FIXED | Expected-severity map covers schema `1.0`/`1.1` and A7 codes; report severities recomputed. | `REPORT_INCONSISTENT` preflight and integration tests. |
| B9-7 | FIXED | Bounded JSON CLI input (4 MiB, depth 64, 200,000 nodes), iterative pre-scan, fixed errors. | CLI input-limit tests. |
| B9-8 | FIXED | PR base retargeted from `feature/xinsta-core` to `main`; `origin/main` merged without force; duplicated Xinsta Core commits removed from the PR diff. | `12ac403` clean diff; PR base retarget. Historical objects retained because no force/rewrite is permitted. |

## PR #10 — Integration (Phase C)

| ID | Status | Fix | Regression evidence |
| --- | --- | --- | --- |
| C-1 | FIXED | Direct `IpaInspectionReport.to_dict()` consumption by `evaluate()` with no reshaping. | `test_real_analyzer_report_feeds_approved_preflight`, CLI acceptance test. |
| C-2 | FIXED | Exact inspected-byte SHA-256 binding; appended archive bytes invalidate the manifest. | `test_hash_binding_uses_the_real_artifact_hash`, `test_modified_archive_bytes_break_the_exact_hash_binding`. |
| C-3 | FIXED | Forged authorization, unexpected fields, unsafe identifiers, malformed report, ambiguous root and unsupported architecture rejected. | Integration rejection tests. |
| C-4 | FIXED | Analyzer schema `1.1` and legacy `1.0` accepted; unknown schema rejected without echo. | `test_current_and_legacy_report_schemas_are_accepted`. |
| C-5 | FIXED | No private paths, secret-looking values or local directories copied into output. | Warning-retention and CLI private-path tests, plus rejection no-echo assertions. |
| C-6 | FIXED | Plan remains `dry_run`, `execution_permitted = false`, advisory authorization, blocked execution steps. | First integration test and B9 authorization tests. |

## Not code findings — owner/external blockers

| ID | Status | Blocker |
| --- | --- | --- |
| O-1 | BLOCKED | Written owner authorization is required before any merge or readiness-to-merge transition. |
| O-2 | BLOCKED | Signing identity, provisioning profile and registered UDID are unavailable. |
| O-3 | BLOCKED | No approved injection/implantation method or verified hook path exists. |
| O-4 | BLOCKED | Physical iPhone 13 validation requires written scope and all device prerequisites. |
