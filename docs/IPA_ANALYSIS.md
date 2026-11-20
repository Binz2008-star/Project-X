# IPA Analysis Engine — architecture and operating notes

Status: **Phase 1 implemented, verified locally and against the reference IPA; no database
changes in this increment.** This document describes what the code does today and what is
explicitly out of scope.

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
- A cleared `cryptid` means the App Store encryption wrapper has been removed. It says
  nothing about who did it.

## 2. Module map

| Module | Responsibility |
| --- | --- |
| `project_x/ipa/safety.py` | Bounded ZIP reader. Validates raw central-directory names (including Windows backslash paths that `zipfile` otherwise silently normalises), entry counts/sizes, compression ratios, encryption flags, symlink modes and duplicate names. |
| `project_x/ipa/macho.py` | Minimal Mach-O reader: thin and universal binaries, 32/64-bit, both endiannesses. Extracts architecture, file type, `LC_BUILD_VERSION`/`LC_VERSION_MIN_IPHONEOS`, rpaths, dylib references, encryption info, UUID and a code-signature load-command flag. |
| `project_x/ipa/bundle.py` | Locates `Payload/*.app`, reads `Info.plist`, builds the identity, and inventories `.appex`, `.framework` and `.bundle` directories with their own plists and signature coverage. |
| `project_x/ipa/collisions.py` | Resolves `@rpath`/`@executable_path` references against embedded frameworks, reports protected basenames, unresolved dependencies and duplicate basenames. It flags potential collisions before any injection; static basename analysis alone does not prove an injection will work. |
| `project_x/ipa/signing.py` | Reads signature *metadata*: `CodeResources`, provisioning-profile summary, FairPlay `SC_Info/`, nested bundle coverage. Never verifies. |
| `project_x/ipa/report.py` | The versioned JSON contract (`schema_version = "1.0"`) and severity-ordered findings. This is the interface Phase 2 registries should consume. |
| `project_x/ipa/inspector.py` | Orchestration and SHA-256. |
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

## 6. Reference IPA result (independently re-verified)

A read-only inspection of the owner-provided third-party reference IPA confirmed the
previously reported identity, version/build, minimum iOS version, arm64-only architecture
and `cryptid = 0`. The archive contained 3,563 entries, 8 extensions, 6 frameworks and 9
resource bundles. Signature metadata (`CodeResources`) was present, no provisioning profile
and no `SC_Info` were present, and all 14 nested extensions/frameworks had signature
metadata. No unresolved `@rpath` dependency and no duplicate framework basename was found.

Findings were informational only: the encryption flag is cleared and several embedded
framework basenames are already linked by the host binary. Neither finding establishes
tweak compatibility, and signature validity is not asserted. The full hash and inventory
are kept in the owner's local verification log rather than in this public document. This
also confirms every studied reference project targets an older app version; no dynamic test
has been run.

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
