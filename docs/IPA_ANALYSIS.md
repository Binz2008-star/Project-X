# IPA Analysis Engine — architecture and operating notes

Status: **Phase 1 implemented and verified with synthetic fixtures in public CI; no database
changes in this increment.** An earlier read-only check of an owner-provided artifact is
retained in the owner's private log and is not reproducible from this repository. This
document describes what the code does today and what is explicitly out of scope.

## 1. Scope and guarantees

The engine is a **read-only, offline structural inspector** for ZIP-based iOS application
archives. It answers "what does this bundle declare about itself?" — never "is this binary
safe?" and never "is this signature valid?".

Guarantees:

- The input file is opened for reading only. Nothing is extracted, repackaged, relocated or
  written back. No path from the archive is ever used to create a file.
- The entire implementation is Python standard library, so it runs on Windows, macOS and
  Linux CI without Xcode, Theos, dpkg or any third-party binary.
- Every read is bounded by hard ceilings (entry count, uncompressed size, individual entry
  size, compression ratio, read size). Exceeding a ceiling stops the analysis with a coded
  error rather than consuming unbounded memory or time.
- Report output contains no local filesystem path and no binary payload, only metadata.

Non-guarantees, stated in every report:

- Static inspection **does not prove the absence of malicious code**.
- Presence of `_CodeSignature` **does not verify a signature**. Verification requires the
  Apple trust chain and a signing identity; reports always carry
  `signing.verification.verified = false`.
- A cleared `cryptid` means the Mach-O encryption flag is unset. It is not proof of how that
  state was reached, who changed it, or whether any wrapper was removed.

## 2. Module map

| Module | Responsibility |
| --- | --- |
| `project_x/ipa/safety.py` | Bounded ZIP reader. Validates raw central-directory names (including Windows backslash paths that `zipfile` otherwise silently normalises), entry counts/sizes, compression ratios, encryption flags, symlink modes and duplicate names. |
| `project_x/ipa/macho.py` | Minimal Mach-O reader: thin and universal binaries, 32/64-bit, both endiannesses. Extracts architecture, file type, `LC_BUILD_VERSION`/`LC_VERSION_MIN_IPHONEOS`, rpaths, dylib references, encryption info, UUID and a code-signature load-command flag. |
| `project_x/ipa/bundle.py` | Locates `Payload/*.app`, reads `Info.plist`, builds the identity, and inventories `.appex`, `.framework` and `.bundle` directories with their own plists and signature coverage. |
| `project_x/ipa/collisions.py` | Resolves `@rpath`/`@executable_path` references against embedded frameworks, reports protected basenames, unresolved dependencies and duplicate basenames. It flags potential collisions before any injection; static basename analysis alone does not prove an injection will work. |
| `project_x/ipa/signing.py` | Reads signature *metadata*: `CodeResources`, provisioning-profile summary, FairPlay `SC_Info/`, nested bundle coverage. Never verifies. |
| `project_x/ipa/report.py` | The versioned JSON contract (`schema_version = "1.1"`) and severity-ordered findings. This is the interface Phase 2 registries should consume. |
| `project_x/ipa/inspector.py` | Orchestration. The archive is opened once; parsing, raw-name validation, entry reads and hashing use the same descriptor. |
| `scripts/inspect_ipa.py` | CLI: `--summary`, `--json`, `--no-hash`, `--fail-on-critical`, limit overrides. |

## 3. Safety model

`ArchiveSafetyError` stops analysis. `findings` record suspicious-but-readable structure.
Examples of hard refusals: path traversal, absolute or backslash paths in the **raw** ZIP
central directory, encrypted entries, unsupported compression methods, symlink-to-file
entries (warning), duplicate names (warning), compression ratio above the ceiling, and
entry/read-size overruns.

The raw central-directory scan exists because Python's `zipfile` rewrites `\` to `/` on every
platform. Validating only `ZipFile.infolist()` would miss a Windows traversal attempt
entirely. Both classic and ZIP64 end-of-central-directory records are parsed.

### 3.1 Review-closure corrections (A7-1 … A7-7 and independent re-review)

- **A7-1 / provenance:** the archive path is opened once. `zipfile`, the raw central-directory
  scan, all entry reads and the SHA-256 hash use the same descriptor. A size/mtime change
  detected before completion raises `ARCHIVE_CHANGED_DURING_ANALYSIS` rather than returning a
  report that mixes bytes from two files.
- **A7-2 / ambiguity:** all top-level `Payload/*.app/` directories are derived from entry names
  and implied directories, including roots without a readable `Info.plist`. More than one such
  root raises `AmbiguousAppRootError`; the CLI maps it to `REFUSED [AMBIGUOUS_APPLICATION_ROOT]`.
  Nested `.app` bundles are still inventoried normally.
- **A7-3 / metadata types:** main and nested identity values are type- and shape-checked. Wrong
  types, empty strings, bad `UIDeviceFamily` entries and bad platform lists raise
  `MalformedInfoPlistError`; the CLI maps it to `REFUSED [INVALID_INFO_PLIST_VALUE]`. Nested
  property-list read failures are skipped without echoing parser text into the report.
- **A7-4 / unreadable profiles:** a present but unparsable `embedded.mobileprovision` emits a
  `PROVISIONING_PROFILE_UNREADABLE` warning with a fixed reason (`PLIST_MISSING`,
  `PLIST_INVALID` or `READ_ERROR`). No parser text or profile contents are copied.
- **A7-5 / signing names:** `nested_bundles_signed` is replaced by
  `nested_bundles_with_signature_metadata`, `app_signature_file_count` by
  `code_signature_entry_count`, and `is_xcode_managed` by `provisions_all_devices`. These
  names describe metadata presence, not signature validity. The report schema is now `1.1`.
- **A7-6 / output safety:** `--json` writes to a temporary file in the destination directory.
  The input descriptor identity is captured before analysis and checked again immediately before
  publication. The report is published with a no-overwrite hard link; an existing target,
  including a symlink, is never removed or replaced. A concurrent rename that puts the input
  archive at the target makes publication fail closed with `OUTPUT_COLLIDES_WITH_INPUT` or
  `OUTPUT_WRITE_FAILED`; the archive bytes are never deleted. The output directory must be
  controlled by the caller.
- **A7-7 / weak dependencies:** dependency refs retain their Mach-O load-command `kind`.
  Required unresolved `@rpath` references remain `UNRESOLVED_RPATH_DEPENDENCY` (critical);
  weak ones emit `WEAK_UNRESOLVED_RPATH_DEPENDENCY` (warning). CPU subtype `1` is normalised
  to `arm64` instead of the misleading `arm64v8`.

### 3.2 Independent re-review corrections

| ID | Correction | Regression evidence |
| --- | --- | --- |
| A7-R1 | Nested `.appex`/`.framework`/`.bundle` plists now use the same typed string validation as the main `Info.plist`, so invalid identity values cannot crash the CLI or produce non-string report fields. | Parametrised nested-plist tests plus CLI mapping test. |
| A7-R2 | App-root detection no longer requires an `Info.plist` to infer a root; a second top-level `.app/` directory is ambiguous even when it contains only arbitrary files. | Root-without-plist inspection and CLI tests; existing nested-app counter-test retained. |
| A7-R3 | Report publication rechecks the captured input identity, uses a no-overwrite hard link, and refuses to replace a target recreated during publication. | Race test that renames the input onto the output immediately before publication; static symlink test retained. |
| A7-R4 | Provisioning-profile `Name` and `ExpirationDate` are strictly typed. A parseable profile with non-string/date values is refused with the fixed `PLIST_INVALID` reason; `to_dict()` cannot emit non-string fields or raise on `to_json()`. | Parametrised malformed-profile tests plus a valid-date round-trip test. |
| A7-R5 | The CLI uses a safe argument parser and a fixed `FILE_NOT_FOUND` message; raw arguments, unknown options and private paths are never echoed. | CLI tests for invalid numeric options, unknown options and missing files under a private-looking directory. |
| A7-R6 | Publication never unlinks the target: an existing report or symlink is refused, so no window exists between a collision check and a destructive unlink. | Existing-target, symlink, no-unlink tracer and publication-race tests. |
| A7-R7 | All input-path I/O errors, not only `FileNotFoundError`, produce a fixed refusal without echoing the path or a traceback. | Private-directory CLI test. |
| A7-R8 | Semantically invalid numeric limits (`0`, negative) produce fixed `INVALID_ARGUMENTS` instead of an uncaught `ValueError`. | Parametrised CLI limit tests. |

Downstream consumers must accept schema `1.1`. No private field names, local paths or raw
parser text are emitted by the new refusal codes.

## 4. Phase 2 foundation

No tables, migrations or API routes are added here. The foundation is the stable report
contract: `schema_version`, `artifact.sha256` for provenance, `identity` for the application
version registry, `bundles`/`dependencies` for compatibility checks, and `signing` for
extension-signing requirements. A future migration can store these fields without changing
the analysis engine. IPA binaries remain outside the repository; only hashes and metadata
may be recorded.

## 5. Verification performed

Commands run on the feature branch with the repository virtual environment:

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/test_ipa_analysis.py
.\.venv\Scripts\python.exe -m scripts.inspect_ipa '<owner-provided-reference-ipa>' --summary
.\.venv\Scripts\python.exe -m pytest -q tests/test_api.py tests/test_neon_staging_check.py
.\.venv\Scripts\python.exe -m unittest discover -s tests -p test_licensing.py -v
.\.venv\Scripts\python.exe -m scripts.export_openapi --check
```

The analysis tests use only synthesised fixtures: a hand-built Mach-O header and ZIP
containers generated in `tmp_path`. No third-party IPA is committed, downloaded or required
by CI.

## 6. Earlier owner-provided artifact check (not CI-reproducible)

An earlier local, read-only run against an owner-provided artifact was recorded in the
owner's private verification log. It observed the identity, version/build, minimum iOS
version, arm64 architecture and `cryptid = 0` reported previously, plus the archive counts
and nested signature metadata described in that log. That run is **not** reproducible in
public CI because no third-party bytes are committed and no private path, hash or device
identifier is published here. It is historical evidence only: it does not prove signature
validity, tweak compatibility, or behaviour on any device, and no dynamic test was run.

All claims verified by this repository's CI come from synthetic, owned fixtures generated in
`tmp_path`. The reference check is mentioned solely to explain the origin of the analyzer
requirements, not as a pass criterion for this PR.

## 7. Windows vs macOS division

**Possible on Windows today:** IPA analysis, report generation, registry/hash bookkeeping,
tweak manifest authoring, compatibility matrix logic, signing-metadata inventory, install
workflow modelling, tests and all backend API work.

**Requires macOS/Xcode:** compiling Swift/Objective-C sources or Theos tweaks, codesign
invocation with a real identity, provisioning-profile handling, generating an installable
IPA, and any device-side installation or launch. This machine has no `xcodebuild`, `clang`,
`make`, `ruby`, `pod` or Theos, so no build proof of concept can be claimed here.

## 8. Smallest practical iOS proof of concept (not started)

On a macOS host with an authorised signing identity: build a small owned sample app with a
custom display name, icon and unique bundle id, add one optional dylib with a name that does
not collide with a host framework, embed one extension, produce a signed IPA, record its
SHA-256, install it on the owner's iPhone 13 in Developer Mode, and verify launch and
extension behaviour. The third-party reference IPA stays analysis-only and is never used
as a build input in this increment.

## 9. Blockers and next increment

- No macOS/Xcode host, no authorised signing identity, no owned sample iOS app in the repo.
- Real-device testing requires explicit owner authorisation; no device has been changed.
- Neon staging integration remains unexecuted by this agent; no Neon production operation
  was attempted.

Recommended next increment: Phase 2 registry schemas and API endpoints that ingest
`IpaInspectionReport` JSON (SQLite/ephemeral Postgres in CI only), followed by an independent
review before any merge proposal.
