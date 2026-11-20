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
| `tests/test_build_manager_preflight.py` | 40 synthetic-payload tests; no third-party IPA or credential needed. |
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

The report is the versioned `IpaInspectionReport` (`schema_version = "1.0"`) defined by the read-only analysis engine. Only these fields are consumed: `artifact.sha256`, `identity.{bundle_id,version,build_number,minimum_os,executable}`, `macho.slices[]`, `signing.verification`, `dependencies.{unresolved_rpath_dependencies,duplicate_framework_basenames}`, `findings[].{code,severity}`, and `interpretation.malware_verdict`. Everything else is ignored so that provisioning-profile details, local names, and other private metadata cannot leak into the plan.

## Fail-closed rules

| Check | Rejection code |
| --- | --- |
| Manifest shape, schema, boolean authorization, exact ID/hash/identity | `MANIFEST_INVALID` |
| Report shape or unsupported schema | `REPORT_INVALID` |
| Any bundle other than an owned test package | `BUNDLE_ID_NOT_ALLOWED` |
| Identity or hash differs from the manifest | `BUNDLE_ID_MISMATCH`, `VERSION_MISMATCH`, `BUILD_MISMATCH`, `SHA256_MISMATCH` |
| Deployment target below iOS 16.3 | `MINIMUM_OS_TOO_LOW` |
| Missing/invalid main executable or non-arm64/encrypted slice | `MAIN_EXECUTABLE_*` |
| Critical structural finding from the analyzer | `CRITICAL_ANALYSIS_FINDING` |
| Report claims signature verification or a malware verdict | `SIGNING_VERIFICATION_CLAIM`, `MALWARE_VERDICT_CLAIM` |
| Unresolved `@rpath` dependency | `UNRESOLVED_RPATH_DEPENDENCY` |

Warnings and duplicate framework basenames are retained as `review_findings`; they do not silently disappear. Multiple blockers are reported together rather than stopping at the first one.

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

Exit codes: `0` preflight passed, `2` preflight rejected, `1` input unreadable or malformed JSON. On input errors the CLI prints only an error kind; it does not echo private paths or decoder details. Windows syntax uses `--basetemp` because the default pytest temp root can be ACL-restricted; CI on Linux needs no override.

## Verification

- Local: `40 passed` for `tests/test_build_manager_preflight.py` on Python 3.14 (2026-11-21).
- CI: add run IDs here after the first workflow run on this branch.

## Security and compatibility considerations

- Trust boundary: the tool trusts the *structure* of the analyzer report but verifies that the analyzer did not claim signature verification or a malware verdict. A forged report can still misstate facts; the SHA-256 binding to an owner manifest limits casual substitution but is not a cryptographic signature.
- No third-party IPA is inspected, copied, or committed in these tests. Fixtures are hand-built JSON.
- No signing identity, provisioning profile, UDID, Apple ID, or device is touched.
- `XinstaCore` remains a standalone, unsigned dylib. This tool does not claim any loader/rpath wiring, injection, or hook.

## Outstanding risks and next milestone

1. Independent Model 1 review of this increment (pending).
2. An owner-owned, buildable iOS test application must exist before any real integration rehearsal. The fictional `demo.owned` identity is only a contract fixture.
3. Signing identity, provisioning profile, registered UDID, and written device-authorization scope remain unavailable — all plan steps that need them stay `blocked`.
4. No approved injection/implantation method or verified hook path exists; X Settings remains a standalone simulator-tested controller.
5. Next executable milestone: extend this plan into a *local-only, owned-app* integration rehearsal that produces a reproducible artifact manifest and proves the plan’s stepped preconditions, still without signing or device installation.

No merge, deployment, Neon change, signing, repackaging, or device work is authorized by this increment.
