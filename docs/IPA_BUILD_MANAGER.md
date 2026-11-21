# IPA Build Manager — dry-run preflight gate

Status: **fail-closed preflight/planning and bounded unsigned packaging executor implemented and locally tested in the Draft PR stack; no signing, final signed repackage, install, or device action is included.** PR #9 base was retargeted from `feature/xinsta-core` to `main`; its diff now contains only Build Manager files.

## What this increment does

It answers one narrow question: *given an unsigned owner declaration manifest and a read-only inspection report for a specific IPA, is a future integration plan safe enough to send for independent review?* The declaration is an **advisory assertion only**; it is not cryptographic proof of authorization.

The preflight tool consumes bounded JSON only. It never opens an IPA, never extracts, writes, signs, relocates, or installs a bundle, never reads credentials, and never contacts a device or remote service. A passing result produces a deterministic **dry-run plan** whose `execution_permitted` field is always `false`. A separate, fail-closed authorization gate (below) is required before any future execution. The separate packaging executor added for the private pilot is bounded and unsigned: it can write a disposable, distinct IPA for private review but cannot sign, install, or contact a device.

## Files

| File | Purpose |
| --- | --- |
| `project_x/buildmanager/__init__.py` | Public exports for the preflight and authorization APIs. |
| `project_x/buildmanager/preflight.py` | Unsigned-declaration parsing, fail-closed policy checks, deterministic plan builder. |
| `project_x/buildmanager/authorization.py` | Separate fail-closed execution-permit gate; no executor, key or secret. |
| `scripts/build_manager_preflight.py` | Bounded JSON CLI; prints one JSON document to stdout and exits 0/1/2. |
| `tests/test_build_manager_preflight.py` | Synthetic-payload tests; no third-party IPA or credential needed. |
| `tests/test_build_manager_authorization.py` | Fail-closed authorization-gate tests with fixture verifiers only. |
| `.github/workflows/ci.yml` | Adds the preflight test step to the existing isolated CI job. |
| `docs/IPA_BUILD_MANAGER.md` | This document. |

## Input contract

### Unsigned owner declaration manifest (advisory)

```json
{
  "schema_version": "1.0",
  "owner_authorized": true,
  "authorization_id": "AUTH-DEMO-001",
  "expected_identity": {
    "bundle_id": "demo.owned",
    "version": "1.0.0",
    "build_number": "7"
  },
  "expected_sha256": "<64 lower-case hex characters>",
  "rights_basis": "owned-test-package"
}
```

Keys must match exactly. `owner_authorized` must be boolean `true`; wildcard characters are rejected in identity values. Identity-like strings are bounded (at most 256 characters) and rejected if they contain path separators, NUL/control characters, bidi or invisible format controls, secret-looking names or values, or excessive length. Rejections use the fixed code `UNSAFE_IDENTITY_STRING` and never echo the rejected value. The manifest contains **no secret values and no file path** — only the identifier of a declaration that must already exist outside this repository. Passing this check does **not** prove authorization.

### Inspection report

The report is the versioned `IpaInspectionReport` defined by the read-only analysis engine. `schema_version` `1.0`, `1.1` and `1.2` are accepted; `1.1` adds typed dependency references and fix codes, and `1.2` adds bounded URL-scheme and provisioning-profile group summaries for the private-pilot isolation policy. Unknown, missing or malformed schema values are rejected with `REPORT_INVALID` and the raw value is never echoed. Only these fields are consumed: `artifact.sha256`, `identity.{bundle_id,name,display_name,version,build_number,minimum_os,executable,url_schemes}`, `macho.{slice_count,slices[]}`, `bundles.extensions[].bundle_id`, `signing.{provisioning_profile_present,verification,provisioning_profile.{entitlement_keys,app_groups,keychain_access_groups}}`, `dependencies.{unresolved_rpath_dependencies,duplicate_framework_basenames}`, `findings[].{code,severity}`, and `interpretation.malware_verdict`. Group and scheme values are validated and compared against the declaration; their raw values are not copied into the dry-run plan. Everything else is ignored so that local names and other private metadata cannot leak into the plan.

Report hash format is validated identically to the manifest. Finding codes must come from the fixed `KNOWN_ANALYSIS_CODES` allowlist; arbitrary strings are rejected before any result is built. This prevents a crafted code containing a path, secret, or control character from being echoed into `review_findings` or a blocker detail. The allowlist must be updated deliberately when the analyzer contract changes, which is fail-closed by design.

Every known finding code has an entry in `EXPECTED_SEVERITIES`, including the A7 correction codes `WEAK_UNRESOLVED_RPATH_DEPENDENCY` (warning), `PROVISIONING_PROFILE_UNREADABLE` (warning), `ARCHIVE_CHANGED_DURING_ANALYSIS`, `AMBIGUOUS_APPLICATION_ROOT`, and `INVALID_INFO_PLIST_VALUE` (all critical). The report's `severity` is **not trusted**: it is recomputed from the code, and any mismatch is rejected with the fixed code `REPORT_INCONSISTENT`. Raw finding `detail` and `context` are never read or emitted.

## Fail-closed rules

| Check | Rejection code |
| --- | --- |
| Manifest shape, schema, boolean declaration, exact ID/hash/identity | `MANIFEST_INVALID` |
| Report shape, unsupported schema, unknown finding code, malformed hash | `REPORT_INVALID` |
| Unsafe identity-like text (path, control, bidi, secret-like, overlong) | `UNSAFE_IDENTITY_STRING` |
| Report finding severity disagrees with its known code | `REPORT_INCONSISTENT` |
| Any bundle other than an owned test package, the pinned load-only proof identity, or the private pilot | `BUNDLE_ID_NOT_ALLOWED` |
| Pinned proof has the wrong rights basis or an unpinned hash | `RIGHTS_BASIS_NOT_ALLOWED_FOR_LOAD_PROOF`, `SHA256_NOT_PINNED_FOR_LOAD_PROOF` |
| Private pilot has the wrong rights basis, identity, source hash, adapter, or artifact hash | `RIGHTS_BASIS_NOT_ALLOWED_FOR_PRIVATE_PILOT`, `PRIVATE_PILOT_IDENTITY_NOT_PINNED`, `PRIVATE_PILOT_SOURCE_NOT_PINNED`, `PRIVATE_PILOT_ADAPTER_NOT_PINNED`, `PRIVATE_PILOT_ARTIFACT_NOT_DISTINCT` |
| Private pilot declares unsafe coexistence, URL schemes, entitlements, groups, or extensions | `PRIVATE_PILOT_COEXISTENCE_DECLARATION_INVALID`, `PRIVATE_PILOT_*_NOT_ALLOWED`, `PRIVATE_PILOT_*_MISMATCH`, `PRIVATE_PILOT_ENTITLEMENT_MISSING` |
| Owned test package declares the load-only or private-pilot rights basis | `RIGHTS_BASIS_NOT_ALLOWED_FOR_OWNED_TEST` |
| Identity or hash differs from the manifest | `BUNDLE_ID_MISMATCH`, `VERSION_MISMATCH`, `BUILD_MISMATCH`, `SHA256_MISMATCH` |
| Deployment target below iOS 16.3 | `MINIMUM_OS_TOO_LOW` |
| Missing/invalid main executable, non-arm64-family, or encrypted slice | `MAIN_EXECUTABLE_*` |
| Declared slice count differs from recorded slices | `MACHO_SLICE_COUNT_MISMATCH` |
| Critical structural finding from the analyzer (code from allowlist only) | `CRITICAL_ANALYSIS_FINDING` |
| Report claims signature verification or a malware verdict | `SIGNING_VERIFICATION_CLAIM`, `MALWARE_VERDICT_CLAIM` |
| Unresolved required `@rpath` dependency | `UNRESOLVED_RPATH_DEPENDENCY` |

Warnings and duplicate framework basenames are retained as `review_findings`; only allowlisted analyzer codes are copied. A7's `WEAK_UNRESOLVED_RPATH_DEPENDENCY` and `PROVISIONING_PROFILE_UNREADABLE` are warnings; `ARCHIVE_CHANGED_DURING_ANALYSIS`, `AMBIGUOUS_APPLICATION_ROOT` and `INVALID_INFO_PLIST_VALUE` are critical blockers. Unknown manifest key names are reduced to counts, never echoed. Multiple blockers are reported together rather than stopping at the first one.

Architecture acceptance is strict: only `arm64` and `arm64e` slices are valid. The legacy string alias `arm64v8` and CPU subtype `1` are normalised to `arm64`; subtype `2` maps to `arm64e`. A subtype never promotes an explicitly unsupported architecture (`x86_64`, `armv7`, unknown strings, non-strings), and one unsupported slice blocks a mixed-slice report. No IPA bytes are read by preflight; tests build minimal real Mach-O headers locally.

The owned-test allowlist contains only `demo.owned`, the fictional/owned test product used throughout this repository. A separate, narrowly pinned planning exception allows `com.burbn.instagram` version `456.0.0` build `1114925422` only when the manifest declares `load-only-proof` and pins artifact SHA-256 `665a814e13d8c187dce5a78d0e8348f73f9081205b927291d7d5d2bce96eb131`. This exception was scoped by the owner for a private load-only device proof; it does not establish commercial rights, permit hooks or host UI verification, or make the plan executable. See `docs/IG456_LOAD_PROOF_RUNBOOK.md`.

A second development-only exception allows `com.projectx.xinsta.pilot` version
`456.0.0` build `1114925422` with rights basis `private-pilot-installability`.
Its declaration must pin the same source SHA-256, a distinct output hash, adapter
`com.projectx.xinsta.pilot@456.0.0@1114925422`, the single URL scheme
`xinsta-pilot-loadproof`, pilot-only App Groups/extension identifiers, no custom
Keychain groups, and coexistence flags `replace_existing_app = false` and
`preserve_original_data = true`. It is dry-run-only and does not weaken the
production gate or prove device coexistence. See
`docs/IG456_PRIVATE_PILOT.md`. All other third-party bundle identifiers remain
rejected unconditionally.

## Dry-run plan semantics

A passing result has `preflight_passed = true` and a plan with:

- `mode = "dry_run"`, `execution_permitted = false`, `status = "READY_FOR_INDEPENDENT_REVIEW"`.
- `purpose = "owned_test_package"`, `purpose = "load_only_proof"`, or `purpose = "private_pilot_installability"`.
- `authorization.verification = "advisory_declaration_only"` and `authorization.cryptographically_verified = false`. The unsigned declaration is never presented as verified authorization.
- Exact package identity and SHA-256 copied from the validated inputs only.
- `@rpath/libXinstaCore.dylib` recorded as the expected install name, with `hook = false` and `swizzle = false`. The pinned proof uses `com.burbn.instagram@456.0.0@1114925422` and the pilot uses `com.projectx.xinsta.pilot@456.0.0@1114925422`; these are identifiers, not runtime capabilities.
- Ordered steps marked `passed`, `planned`, or `blocked`. The declaration check is `check_owner_declaration` (not a verification step). Staging the dylib and adding a loader rpath are *planned* and require a separate installer review; codesigning, device registration/install, in-host load-marker collection, in-host X Settings verification, and the pilot's unique-bundle isolation check are *blocked* pending credentials, verified authorization and an approved hook path.
- Credential names listed as `provided = false`, `secret = true`. No credential value, local path, or provisioning-profile metadata appears in the output.

Plan schema remains `1.0`; the load-only and private-pilot changes are additive. Existing consumers must ignore the new `purpose` values, the pilot adapter identifier, and the extra blocked steps, and no previously emitted field was removed or retyped. Pilot plans also carry a limitation stating that the distinct bundle identity does not weaken the production gate or prove coexistence. If a strict external JSON-schema consumer exists, validate this additive shape before rollout.

The output is byte-stable for identical inputs: no timestamps, no absolute paths, and no unordered sets in emitted lists.

## Verified authorization gate (separate from preflight)

`project_x/buildmanager/authorization.py` is the only authorization gate. Its API is:

- `require_execution_permit(manifest: dict, verifier: Callable[[dict], VerificationResult] | None = None) -> ExecutionPermit`
- `VerificationResult(cryptographically_verified, method, artifact_sha256, authorization_id, signer, provenance)`
- `ExecutionPermit` with `dry_run_only = True` and `execution_permitted = False`; it has no `execute()` method.

It fails closed with a fixed `AuthorizationVerificationError.code` when there is no verifier (`AUTHORIZATION_VERIFIER_REQUIRED`), the manifest is invalid (`MANIFEST_INVALID`), verification is absent (`AUTHORIZATION_NOT_VERIFIED`), the method is unrecognized (`VERIFICATION_METHOD_UNKNOWN`), the artifact hash or authorization ID is not bound (`ARTIFACT_HASH_NOT_BOUND`, `AUTHORIZATION_ID_NOT_BOUND`), the signer or provenance is not allowlisted (`SIGNER_NOT_ALLOWED`, `PROVENANCE_NOT_ALLOWED`), or the verifier raises (`AUTHORIZATION_VERIFIER_FAILED`). Verifier exception text, paths and secrets are discarded.

Only a caller-injected verifier can produce a permit. Recognized methods, signers and provenance are fixed constants in the module; there is no production signing key, real executor, device access or secret material here. A valid permit records provenance for review and **still cannot execute**: preflight remains advisory and no plan step becomes executable. This gate is not called by preflight and does not change `execution_permitted`.

## Bounded JSON input

Each CLI input is limited to `MAX_INPUT_BYTES = 4 * 1024 * 1024`, `MAX_JSON_DEPTH = 64` and `MAX_JSON_NODES = 200_000` (containers and separators; strings are skipped when counting). The loader reads at most one byte past the limit, pre-scans depth and nodes iteratively before decoding, and catches `RecursionError`. Input errors print only fixed codes: `input_too_large`, `json_too_deep`, `json_too_many_nodes`, `input_unreadable`, or `invalid_arguments`. No path, argument text, or decoder message is printed.

## Usage

```powershell
.\.venv\Scripts\python.exe -m pytest -q --basetemp '<approved-temp-dir>' tests/test_build_manager_preflight.py tests/test_build_manager_authorization.py
.\.venv\Scripts\python.exe -m pytest -q --basetemp '<approved-temp-dir>' tests/test_pilot_package_plan.py tests/test_pilot_package_build.py
.\.venv\Scripts\python.exe -m scripts.build_manager_preflight --manifest manifest.json --report report.json
.\.venv\Scripts\python.exe -m scripts.pilot_package_plan --ipa '<pinned-source>.ipa' --dylib '<reviewed-core>.dylib'
.\.venv\Scripts\python.exe -m scripts.pilot_package_build --ipa '<pinned-source>.ipa' --dylib '<reviewed-core>.dylib' --output '<unsigned-output>.ipa' --rights-reference PRIVATE-REVIEW-REF
```

The builder's `--rights-reference` must be a non-secret private review identifier; it is validated but never stored, embedded, logged, or emitted. The output is unsigned and invalidated for signing. Exit codes: `0` preflight passed, `2` preflight rejected, `1` unreadable/oversized input, invalid JSON shape, or invalid arguments — including unknown flags and missing required flags. Argument errors print only `{"error": "invalid_arguments"}`; file/JSON errors print only a fixed error code. No private path, argument text, or decoder detail is echoed. Windows syntax uses `--basetemp` because the default pytest temp root can be ACL-restricted; CI on Linux needs no override.

## Verification

Load-only policy increment on code head
`3e94db5918b73489f62da70e18b0d011c2536f6d`: local full pytest suite
`308 passed, 30 skipped`; targeted preflight/authorization suites `166 passed`;
legacy licensing `OK (7 tests)`; OpenAPI synchronization passed; `git diff
--check` clean. GitHub Actions run `44856252376` passed on that head with
`58` API tests, `2` staging guards, `87` analyzer tests, `166` preflight and
authorization tests, `18` contract tests, `Ran 7 tests` for licensing, clean
Alembic checks, and synchronized OpenAPI. The documentation-only follow-up head
`114b3b3ac524957982f202b5e580199ba9038cc5` passed CI run `44856414354` with
the same counts. No runtime load evidence is claimed.

### Private-pilot policy increment

On committed head `1c6395e42890be0d65c6f6a5099c3b0c6158fd64`, GitHub Actions
run `44909181636` passed the licensing CI job: API `58 passed`, staging guard
`2 passed`, analyzer `96 passed`, preflight/authorization `193 passed`,
contract `18 passed`, and licensing `Ran 7 tests`. The companion macOS Core run
`44909181721` passed 114 Foundation assertions, 8 simulator XCTests and the
dylib structural checks. Earlier local evidence on the same code:
full pytest `345 passed, 29 skipped`; focused analyzer/preflight/contract suites
`290 passed`; legacy licensing `OK (7 tests)`; OpenAPI synchronization passed;
`git diff --check` clean. Signing, install and runtime evidence remain
`NOT TESTED`. See `docs/IG456_PRIVATE_PILOT.md`.

`project_x/packaging/pilot_plan.py` and `scripts/pilot_package_plan.py` add a
fail-closed dry-run planner for the pinned source plus reviewed unsigned Core
dylib. It verifies the exact dylib SHA-256
`bf58dd04ca747d2d489c92509c9b8e96e2946197ee868c3245fbf5a50a0accff`, emits
read-only packaging steps, reports the source rpath as `already_present`, pins
the display name to `Xinsta`, and marks signing, repackaging, output analysis and
device installation as blocked. `tests/test_pilot_package_plan.py` covers wrong
source/dylib hashes, duplicate rpaths, all accepted Core load-command kinds,
display name, and rpath status. On code head
`3c38ca96116acf4e689a9519e554ab4b8ff899a0`, CI run `44912738704` passed
`10` planner tests and `194` Build Manager tests; the planner run against the
pinned IPA and downloaded dylib reported `execution_permitted=false` with all
four execution steps blocked.

`project_x/packaging/builder.py`, `project_x/packaging/macho_patch.py` and
`scripts/pilot_package_build.py` add a bounded **unsigned** executor for the same
pinned inputs. It requires a non-secret rights reference before changing the
source, rechecks both pinned hashes, rejects output/input path collisions, copies
entries into a new archive, rewrites app/extension/entitlement identities, stages
the reviewed Core dylib, appends one `LC_LOAD_DYLIB` with fail-closed file-offset
relocation, re-analyzes the output, and deletes an output that fails verification.
The source file is never opened for writing. The result is explicitly marked
`signed=false` and `invalidated_requires_resign`; no nested signing, final signed
package, Sideloadly integration, installer, or device action is included.

`tests/test_pilot_package_build.py` covers the unsigned build output, source
integrity, rights-reference rejection, path-safe CLI errors, Mach-O header-segment
mapping, modern linkedit offsets, fileset rejection, and the raw SHA-256 helper.
On the current local worktree the focused builder/planner suite passed
`21 passed`; the full suite passed `366 passed, 30 skipped`; legacy licensing
passed `OK (7 tests)`; OpenAPI synchronization and `git diff --check` passed.
These are local results only; CI for the new code is pending. The third-party
rights and signing blockers remain unchanged, so no installable `Xinsta.ipa` has
been produced. See `docs/IG456_PRIVATE_PILOT.md` and `docs/RIGHTS_REGISTER.md`.

### Independent load-policy review

A fresh read-only review of head `114b3b3ac524957982f202b5e580199ba9038cc5`
returned `APPROVE WITH NON-BLOCKING NOTES`: no blocking findings and no claim
that runtime loading, hooking, host UI presentation, device verification, a
merge, or commercial clearance was achieved. The notes were an additive plan
schema without an explicit compatibility statement, an unrecorded docs-only CI
head, a destructive runbook step relying on a safe `WORK_DIR`, and a numbering
nit. This head documents the additive schema, records the docs-only CI run,
adds a `WORK_DIR` guard, and fixes the numbering. The approval is review
evidence, not merge authorization.

B9 correction and re-review set: `159 passed` for `tests/test_build_manager_preflight.py` together with `tests/test_build_manager_authorization.py` using the repository virtualenv on 2026-11-21; combined API/staging run `31 passed, 29 skipped`; `git diff --check` clean. CI on the earlier B9 head passed push run `44841872361` and PR run `44841879766`. The later re-review corrections and their final-head CI runs are recorded in the PR body.

Earlier local/CI evidence below applies to prior commits only and does not cover the B9 changes:

- Local after the review fixes: `51 passed` for `tests/test_build_manager_preflight.py` on Python 3.14.7 (2026-11-21). Earlier full local suite before those fixes: `71 passed, 29 skipped` combined; legacy licensing `OK (7 tests)`; `OpenAPI schema matches implementation`; `git diff --check` clean.
- CI on code head `d600c2039aadc7e56194ea4618f8c74d0cfca029`: push run `44835102952` **SUCCESS** and PR run `44835108953` **SUCCESS** — `41 passed` preflight, `58 passed` API, `2 passed` staging guard, `Ran 7 tests` licensing, both Alembic checks clean, OpenAPI in sync.
- CI on documentation-only head `f5787c975e2516f0f975b720e16be1a9fdc4f4cd`: push run `44835319318` **SUCCESS** and PR run `44835326639` **SUCCESS** with the same counts.
- CI on review-fix code head `d9db3445c6ec5029456849e7ba0501ffcf2f7613`: push run `44836339224` **SUCCESS** and PR run `44836348720` **SUCCESS** — `51 passed` preflight, `58 passed` API, `2 passed` staging guard, `Ran 7 tests` licensing, both Alembic checks clean, OpenAPI in sync. Any later documentation-only commit does not change this code evidence.
- Earlier commits `fe31227`, `d600c20`, and `f5787c9` have green runs but are superseded.

## Independent review closure (first pass)

The first independent review returned `REQUEST CHANGES` with two Medium findings and one Low finding. All are addressed:

| Finding | Status | Fix | Evidence |
| --- | --- | --- | --- |
| Unvalidated report/manifest strings copied into output | FIXED | `KNOWN_ANALYSIS_CODES` allowlist in `preflight.py`; unknown finding codes rejected; unknown manifest keys reduced to counts; strict report hash format; slice-count cross-check; arm64e accepted explicitly | New tests for secret/path-like finding codes, secret manifest key names, hash format, and slice-count mismatch |
| CLI argument parsing bypassed the documented exit code and echoed paths | FIXED | `SafeArgumentParser.error()` raises `InvalidArguments`; CLI returns 1 with a generic JSON error for unknown/missing arguments | New CLI tests for extra and missing arguments containing private paths |
| Verification section referenced a stale head | FIXED | This section now distinguishes code head from documentation-only head and requires fresh IDs for the review-fix commit | This document |

Independent re-review at code head `d9db3445c6ec5029456849e7ba0501ffcf2f7613` returned **APPROVE** with no Critical, High, Medium, or Low findings. The reviewer confirmed the three fixes, verified that the new tests fail against the pre-fix code, checked the analyzer finding codes against the then-current allowlist, and verified CI runs `44836339224`, `44836348720`, `44836590901`, and `44836598327` from actual logs. That approval predates the B9 changes; the allowlist now also covers the A7 correction codes.

No merge or deployment is implied by this approval. PR #9 remains DRAFT pending explicit owner authorization.

## B9 closure summary

| ID | Status | Fix |
| --- | --- | --- |
| B9-1 | FIXED | Advisory declaration labelled explicitly; no cryptographic authorization claim. |
| B9-2 | FIXED | Fail-closed `authorization.py` permit gate; default reject; valid permit still dry-run-only. |
| B9-3 | FIXED | Analyzer-to-preflight tests remain only in PR #10. |
| B9-4 | FIXED | Bounded, output-safe identity strings with fixed rejection codes. |
| B9-5 | FIXED | arm64/arm64e normalization and subtype `1` handling; unsupported architectures blocked. |
| B9-6 | FIXED | Expected-severity map covers schemas `1.0`/`1.1`/`1.2` and A7 codes; report severities not trusted. |
| B9-7 | FIXED | Bounded JSON CLI input with iterative pre-scan and fixed errors. |
| B9-8 | FIXED | PR #9 base retargeted to `main`; duplicated Xinsta Core commits removed from the PR diff without history rewrite. |

## B9 re-review corrections

The fresh independent review of the B9 head returned `REQUEST CHANGES`. Each finding is closed in code and regression tests:

| ID | Status | Fix |
| --- | --- | --- |
| B9-R1 | FIXED | `schema_version` is type-checked before allowlist membership; unhashable values fail closed as `REPORT_INVALID` instead of raising `TypeError`. |
| B9-R2 | FIXED | `report.macho.slices` must be a list of JSON objects before slice inspection; non-list values fail closed as `REPORT_INVALID`. |
| B9-R3 | FIXED | Bounded JSON loading maps `ValueError` from oversized integer literals and malformed JSON to the fixed `input_unreadable` error. |
| B9-R4 | FIXED | Verifier-raised codes are accepted only from the fixed allowlist; path-like or arbitrary codes reduce to `AUTHORIZATION_VERIFIER_FAILED`. |
| B9-R5 | FIXED | Verifier-supplied method, signer and provenance values are string-checked before allowlist membership. |
| B9-R6 | FIXED | Verification documentation no longer claims the branch was unpushed and cites the actual green CI runs. |
| B9-R7 | FIXED | Documentation states that report schemas `1.0`, `1.1`, and `1.2` are accepted. |

## Security and compatibility considerations

- Trust boundary: the tool trusts the *structure* of the analyzer report but verifies that the analyzer did not claim signature verification or a malware verdict. A forged report can still misstate facts; the SHA-256 binding to an owner declaration limits casual substitution but is not a cryptographic signature. The unsigned declaration is advisory and is not proof of authorization; `authorization.py` is the separate, fail-closed gate and has no executor.
- No third-party IPA is inspected, copied, or committed in these tests. Fixtures are hand-built JSON; the pinned exception stores only identity metadata and a public artifact hash.
- No signing identity, provisioning profile, UDID, Apple ID, or device is touched.
- `XinstaCore` remains a standalone, unsigned dylib. This tool does not claim any loader/rpath wiring, injection, or hook.
- The pinned load-only proof is a planning allowance for a private host runbook. It does not change `execution_permitted`, authorize a hook, prove runtime loading, or permit a merge.

## Outstanding risks and next milestone

1. Independent review of the earlier increment is complete: first pass `REQUEST CHANGES`, re-review **APPROVE** with no remaining findings. This B9 increment is not yet independently reviewed. Owner approval is still required for any merge or later integration stage; the unsigned declaration is not that approval.
2. The analyzer and preflight now coexist in the converged read-only tree. Real analyzer output from synthetic owned fixtures is exercised end to end by `tests/test_build_manager_integration.py`; report schemas `1.0` and `1.1` are accepted. See `docs/INTEGRATION_READINESS.md`.
3. An owner-owned, buildable iOS test application must exist before any real integration rehearsal. The fictional `demo.owned` identity is only a contract fixture.
4. Signing identity, provisioning profile, registered UDID, and written device-authorization scope are supplied only on the private macOS host; they are not read or stored by this repository, and all plan steps that need them stay `blocked`.
5. A load-command insert method is scoped for the pinned proof, but no hook path exists; X Settings remains a standalone simulator-tested controller.
6. Next executable milestone: run the private load-only proof in `docs/IG456_LOAD_PROOF_RUNBOOK.md`, collect the constructor marker from the target process, and keep raw evidence outside the repository.

No merge, deployment, Neon change, signing, repackaging, or device work is authorized by this increment.
