# IPA Build Manager — dry-run preflight gate

Status: **isolated preflight/planning increment implemented and locally tested; no build, sign, repackage, install, or device action is included.** This branch stacks on the Xinsta Core draft PR because it inherits the same safety boundary; it does not change that PR.

## What this increment does

It answers one narrow question: *given an unsigned owner declaration manifest and a read-only inspection report for a specific IPA, is a future integration plan safe enough to send for independent review?* The declaration is an **advisory assertion only**; it is not cryptographic proof of authorization.

The tool consumes bounded JSON only. It never opens an IPA, never extracts, writes, signs, relocates, or installs a bundle, never reads credentials, and never contacts a device or remote service. A passing result produces a deterministic **dry-run plan** whose `execution_permitted` field is always `false`. A separate, fail-closed authorization gate (below) is required before any future execution, and even a valid permit is dry-run-only because this repository has no executor.

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

The report is the versioned `IpaInspectionReport` defined by the read-only analysis engine. `schema_version` `1.0` and `1.1` are both accepted; `1.1` adds typed dependency references and fix codes without changing the fields consumed here. Unknown, missing or malformed schema values are rejected with `REPORT_INVALID` and the raw value is never echoed. Only these fields are consumed: `artifact.sha256`, `identity.{bundle_id,name,display_name,version,build_number,minimum_os,executable}`, `macho.{slice_count,slices[]}`, `signing.verification`, `dependencies.{unresolved_rpath_dependencies,duplicate_framework_basenames}`, `findings[].{code,severity}`, and `interpretation.malware_verdict`. Everything else is ignored so that provisioning-profile details, local names, and other private metadata cannot leak into the plan.

Report hash format is validated identically to the manifest. Finding codes must come from the fixed `KNOWN_ANALYSIS_CODES` allowlist; arbitrary strings are rejected before any result is built. This prevents a crafted code containing a path, secret, or control character from being echoed into `review_findings` or a blocker detail. The allowlist must be updated deliberately when the analyzer contract changes, which is fail-closed by design.

Every known finding code has an entry in `EXPECTED_SEVERITIES`, including the A7 correction codes `WEAK_UNRESOLVED_RPATH_DEPENDENCY` (warning), `PROVISIONING_PROFILE_UNREADABLE` (warning), `ARCHIVE_CHANGED_DURING_ANALYSIS`, `AMBIGUOUS_APPLICATION_ROOT`, and `INVALID_INFO_PLIST_VALUE` (all critical). The report's `severity` is **not trusted**: it is recomputed from the code, and any mismatch is rejected with the fixed code `REPORT_INCONSISTENT`. Raw finding `detail` and `context` are never read or emitted.

## Fail-closed rules

| Check | Rejection code |
| --- | --- |
| Manifest shape, schema, boolean declaration, exact ID/hash/identity | `MANIFEST_INVALID` |
| Report shape, unsupported schema, unknown finding code, malformed hash | `REPORT_INVALID` |
| Unsafe identity-like text (path, control, bidi, secret-like, overlong) | `UNSAFE_IDENTITY_STRING` |
| Report finding severity disagrees with its known code | `REPORT_INCONSISTENT` |
| Any bundle other than an owned test package | `BUNDLE_ID_NOT_ALLOWED` |
| Identity or hash differs from the manifest | `BUNDLE_ID_MISMATCH`, `VERSION_MISMATCH`, `BUILD_MISMATCH`, `SHA256_MISMATCH` |
| Deployment target below iOS 16.3 | `MINIMUM_OS_TOO_LOW` |
| Missing/invalid main executable, non-arm64-family, or encrypted slice | `MAIN_EXECUTABLE_*` |
| Declared slice count differs from recorded slices | `MACHO_SLICE_COUNT_MISMATCH` |
| Critical structural finding from the analyzer (code from allowlist only) | `CRITICAL_ANALYSIS_FINDING` |
| Report claims signature verification or a malware verdict | `SIGNING_VERIFICATION_CLAIM`, `MALWARE_VERDICT_CLAIM` |
| Unresolved required `@rpath` dependency | `UNRESOLVED_RPATH_DEPENDENCY` |

Warnings and duplicate framework basenames are retained as `review_findings`; only allowlisted analyzer codes are copied. A7's `WEAK_UNRESOLVED_RPATH_DEPENDENCY` and `PROVISIONING_PROFILE_UNREADABLE` are warnings; `ARCHIVE_CHANGED_DURING_ANALYSIS`, `AMBIGUOUS_APPLICATION_ROOT` and `INVALID_INFO_PLIST_VALUE` are critical blockers. Unknown manifest key names are reduced to counts, never echoed. Multiple blockers are reported together rather than stopping at the first one.

Architecture acceptance is strict: only `arm64` and `arm64e` slices are valid. The legacy string alias `arm64v8` and CPU subtype `1` are normalised to `arm64`; subtype `2` maps to `arm64e`. A subtype never promotes an explicitly unsupported architecture (`x86_64`, `armv7`, unknown strings, non-strings), and one unsupported slice blocks a mixed-slice report. No IPA bytes are read by preflight; tests build minimal real Mach-O headers locally.

The allowlist currently contains only `demo.owned`, the fictional/owned test product used throughout this repository. Third-party bundle identifiers such as `com.burbn.instagram` are rejected unconditionally: `docs/RIGHTS_REGISTER.md` records that commercial rights are not established, and the owner has not supplied a written authorization artifact to this tool.

## Dry-run plan semantics

A passing result has `preflight_passed = true` and a plan with:

- `mode = "dry_run"`, `execution_permitted = false`, `status = "READY_FOR_INDEPENDENT_REVIEW"`.
- `authorization.verification = "advisory_declaration_only"` and `authorization.cryptographically_verified = false`. The unsigned declaration is never presented as verified authorization.
- Exact package identity and SHA-256 copied from the validated inputs only.
- `@rpath/libXinstaCore.dylib` recorded as the expected install name, with `hook = false` and `swizzle = false`.
- Ordered steps marked `passed`, `planned`, or `blocked`. The declaration check is `check_owner_declaration` (not a verification step). Staging the dylib and adding a loader rpath are *planned* and require a separate installer review; codesigning, device registration/install, and in-host X Settings verification are *blocked* pending credentials, verified authorization and an approved hook path.
- Credential names listed as `provided = false`, `secret = true`. No credential value, local path, or provisioning-profile metadata appears in the output.

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
.\.venv\Scripts\python.exe -m scripts.build_manager_preflight --manifest manifest.json --report report.json
```

Exit codes: `0` preflight passed, `2` preflight rejected, `1` unreadable/oversized input, invalid JSON shape, or invalid arguments — including unknown flags and missing required flags. Argument errors print only `{"error": "invalid_arguments"}`; file/JSON errors print only a fixed error code. No private path, argument text, or decoder detail is echoed. Windows syntax uses `--basetemp` because the default pytest temp root can be ACL-restricted; CI on Linux needs no override.

## Verification

B9 correction set (this branch): `142 passed` for `tests/test_build_manager_preflight.py` together with `tests/test_build_manager_authorization.py` using the repository virtualenv on 2026-11-21, with `git diff --check` clean. No CI run is claimed for this branch; it has not been pushed.

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

## Security and compatibility considerations

- Trust boundary: the tool trusts the *structure* of the analyzer report but verifies that the analyzer did not claim signature verification or a malware verdict. A forged report can still misstate facts; the SHA-256 binding to an owner declaration limits casual substitution but is not a cryptographic signature. The unsigned declaration is advisory and is not proof of authorization; `authorization.py` is the separate, fail-closed gate and has no executor.
- No third-party IPA is inspected, copied, or committed in these tests. Fixtures are hand-built JSON.
- No signing identity, provisioning profile, UDID, Apple ID, or device is touched.
- `XinstaCore` remains a standalone, unsigned dylib. This tool does not claim any loader/rpath wiring, injection, or hook.

## Outstanding risks and next milestone

1. Independent review of the earlier increment is complete: first pass `REQUEST CHANGES`, re-review **APPROVE** with no remaining findings. This B9 increment is not yet independently reviewed. Owner approval is still required for any merge or later integration stage; the unsigned declaration is not that approval.
2. The analyzer that emits the report lives in the separate Draft PR #7 and is not imported here; integration is by the pinned `schema_version = "1.0"` contract and synthetic payloads only. An end-to-end test with real analyzer output is pending until the branches converge.
3. An owner-owned, buildable iOS test application must exist before any real integration rehearsal. The fictional `demo.owned` identity is only a contract fixture.
4. Signing identity, provisioning profile, registered UDID, and written device-authorization scope remain unavailable — all plan steps that need them stay `blocked`.
5. No approved injection/implantation method or verified hook path exists; X Settings remains a standalone simulator-tested controller.
6. Next executable milestone: extend this plan into a *local-only, owned-app* integration rehearsal that produces a reproducible artifact manifest and proves the plan’s stepped preconditions, still without signing or device installation.

No merge, deployment, Neon change, signing, repackaging, or device work is authorized by this increment.
