# IPA Build Manager — dry-run preflight gate

Status: **isolated preflight/planning increment implemented and locally tested; no build, sign, repackage, install, or device action is included.** This branch stacks on the Xinsta Core draft PR because it inherits the same safety boundary; it does not change that PR.

## What this increment does

It answers one narrow question: *given an owner authorization manifest and a read-only inspection report for a specific IPA, is a future integration plan safe enough to send for independent review?*

The tool consumes JSON only. It never opens an IPA, never extracts, writes, signs, relocates, or installs a bundle, never reads credentials, and never contacts a device or remote service. A passing result produces a deterministic **dry-run plan** whose `execution_permitted` field is always `false`.

## Files

| File | Purpose |
| --- | --- |
| `project_x/buildmanager/__init__.py` | Public exports for the preflight API. |
| `project_x/buildmanager/preflight.py` | Manifest parsing, fail-closed policy checks, deterministic plan builder. |
| `scripts/build_manager_preflight.py` | CLI; prints one JSON document to stdout and exits 0/1/2. |
| `tests/test_build_manager_preflight.py` | 51 synthetic-payload tests; no third-party IPA or credential needed. |
| `.github/workflows/ci.yml` | Adds the preflight test step to the existing isolated CI job. |
| `docs/IPA_BUILD_MANAGER.md` | This document. |

## Input contract

### Owner authorization manifest

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

Keys must match exactly. `owner_authorized` must be boolean `true`; wildcard characters are rejected in identity values. The manifest contains **no secret values and no file path** — only the identifier of an authorization that must already exist outside this repository.

### Inspection report

The report is the versioned `IpaInspectionReport` (`schema_version = "1.0"`) defined by the read-only analysis engine. Only these fields are consumed: `artifact.sha256`, `identity.{bundle_id,version,build_number,minimum_os,executable}`, `macho.{slice_count,slices[]}`, `signing.verification`, `dependencies.{unresolved_rpath_dependencies,duplicate_framework_basenames}`, `findings[].{code,severity}`, and `interpretation.malware_verdict`. Everything else is ignored so that provisioning-profile details, local names, and other private metadata cannot leak into the plan.

Report hash format is validated identically to the manifest. Finding codes must come from the fixed `KNOWN_ANALYSIS_CODES` allowlist; arbitrary strings are rejected before any result is built. This prevents a crafted code containing a path, secret, or control character from being echoed into `review_findings` or a blocker detail. The allowlist must be updated deliberately when the analyzer contract changes, which is fail-closed by design.

## Fail-closed rules

| Check | Rejection code |
| --- | --- |
| Manifest shape, schema, boolean authorization, exact ID/hash/identity | `MANIFEST_INVALID` |
| Report shape, unsupported schema, unknown finding code, malformed hash | `REPORT_INVALID` |
| Any bundle other than an owned test package | `BUNDLE_ID_NOT_ALLOWED` |
| Identity or hash differs from the manifest | `BUNDLE_ID_MISMATCH`, `VERSION_MISMATCH`, `BUILD_MISMATCH`, `SHA256_MISMATCH` |
| Deployment target below iOS 16.3 | `MINIMUM_OS_TOO_LOW` |
| Missing/invalid main executable, non-arm64-family, or encrypted slice | `MAIN_EXECUTABLE_*` |
| Declared slice count differs from recorded slices | `MACHO_SLICE_COUNT_MISMATCH` |
| Critical structural finding from the analyzer (code from allowlist only) | `CRITICAL_ANALYSIS_FINDING` |
| Report claims signature verification or a malware verdict | `SIGNING_VERIFICATION_CLAIM`, `MALWARE_VERDICT_CLAIM` |
| Unresolved `@rpath` dependency | `UNRESOLVED_RPATH_DEPENDENCY` |

Warnings and duplicate framework basenames are retained as `review_findings`; only allowlisted analyzer codes are copied. Unknown manifest key names are reduced to counts, never echoed. Multiple blockers are reported together rather than stopping at the first one.

The allowlist currently contains only `demo.owned`, the fictional/owned test product used throughout this repository. Third-party bundle identifiers such as `com.burbn.instagram` are rejected unconditionally: `docs/RIGHTS_REGISTER.md` records that commercial rights are not established, and the owner has not supplied a written authorization artifact to this tool.

## Dry-run plan semantics

A passing result has `preflight_passed = true` and a plan with:

- `mode = "dry_run"`, `execution_permitted = false`, `status = "READY_FOR_INDEPENDENT_REVIEW"`.
- Exact package identity and SHA-256 copied from the validated inputs only.
- `@rpath/libXinstaCore.dylib` recorded as the expected install name, with `hook = false` and `swizzle = false`.
- Ordered steps marked `passed`, `planned`, or `blocked`. Staging the dylib and adding a loader rpath are *planned* and require a separate installer review; codesigning, device registration/install, and in-host X Settings verification are *blocked* pending credentials and an approved hook path.
- Credential names listed as `provided = false`, `secret = true`. No credential value, local path, or provisioning-profile metadata appears in the output.

The output is byte-stable for identical inputs: no timestamps, no absolute paths, and no unordered sets in emitted lists.

## Usage

```powershell
.\.venv\Scripts\python.exe -m pytest -q --basetemp '<approved-temp-dir>' tests/test_build_manager_preflight.py
.\.venv\Scripts\python.exe -m scripts.build_manager_preflight --manifest manifest.json --report report.json
```

Exit codes: `0` preflight passed, `2` preflight rejected, `1` unreadable input, malformed JSON, or invalid arguments — including unknown flags and missing required flags. Argument errors print only `{"error": "invalid_arguments"}`; file/JSON errors print only an error kind. No private path, argument text, or decoder detail is echoed. Windows syntax uses `--basetemp` because the default pytest temp root can be ACL-restricted; CI on Linux needs no override.

## Verification

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

Independent re-review at code head `d9db3445c6ec5029456849e7ba0501ffcf2f7613` returned **APPROVE** with no Critical, High, Medium, or Low findings. The reviewer confirmed the three fixes, verified that the new tests fail against the pre-fix code, checked all 46 analyzer finding codes against the allowlist, and verified CI runs `44836339224`, `44836348720`, `44836590901`, and `44836598327` from actual logs. The docs-only head `a0d4585cebf67d4243cb5bb6b54d6c781d092b19` does not change that code evidence.

No merge or deployment is implied by this approval. PR #9 remains DRAFT pending explicit owner authorization.

## Security and compatibility considerations

- Trust boundary: the tool trusts the *structure* of the analyzer report but verifies that the analyzer did not claim signature verification or a malware verdict. A forged report can still misstate facts; the SHA-256 binding to an owner manifest limits casual substitution but is not a cryptographic signature.
- No third-party IPA is inspected, copied, or committed in these tests. Fixtures are hand-built JSON.
- No signing identity, provisioning profile, UDID, Apple ID, or device is touched.
- `XinstaCore` remains a standalone, unsigned dylib. This tool does not claim any loader/rpath wiring, injection, or hook.

## Outstanding risks and next milestone

1. Independent review is complete: first pass `REQUEST CHANGES`, re-review **APPROVE** with no remaining findings. Owner authorization is still required for any merge or later integration stage.
2. The analyzer that emits the report lives in the separate Draft PR #7 and is not imported here; integration is by the pinned `schema_version = "1.0"` contract and synthetic payloads only. A follow-up stacked increment brings the analyzer into the same tree and tests real analyzer output end to end; see `docs/INTEGRATION_READINESS.md`.
3. An owner-owned, buildable iOS test application must exist before any real integration rehearsal. The fictional `demo.owned` identity is only a contract fixture.
4. Signing identity, provisioning profile, registered UDID, and written device-authorization scope remain unavailable — all plan steps that need them stay `blocked`.
5. No approved injection/implantation method or verified hook path exists; X Settings remains a standalone simulator-tested controller.
6. Next executable milestone: extend this plan into a *local-only, owned-app* integration rehearsal that produces a reproducible artifact manifest and proves the plan’s stepped preconditions, still without signing or device installation.

No merge, deployment, Neon change, signing, repackaging, or device work is authorized by this increment.
