# Xinsta Core

Xinsta Core is an iOS-only, modular foundation for authorised enhanced
functionality and an **X Settings** screen. This increment delivers the core
library, a fail-closed compatibility adapter for the Instagram 456.0.0 reference,
an isolated build, and automated tests. It does **not** modify, package, sign, or
install any Instagram application, and it performs **no method swizzling**.

## Scope and safety

- iOS only. Minimum deployment target: iOS 16.3 (matches the analysed IPA).
- No Android, no jailbreak, no storefront, no payment.
- The owner-provided reference IPA was read only through the protected
  `SafeArchive` tooling. No IPA binary, extracted payload, certificate, or
  provisioning profile is stored in this repository.
- The adapter is metadata-only. It rejects a host unless **all** of the
  following match: bundle identifier `com.burbn.instagram`, version `456.0.0`,
  build `1114925422`, and runtime visibility of every required Objective-C name.
  A pass changes only a status value; it does not modify any Instagram class.
- Every feature declares the adapter it is bound to. Features for another
  adapter are filtered out, cannot be toggled, and cannot be presented.
- `compatibilityAccepted == YES` means “the exact host metadata and symbols
  were observed”. It does **not** mean Instagram was hooked, a tweak was
  injected, or X Settings was shown inside Instagram.

## Layout

```
ios/XinstaCore/
  Package.swift                       # minimal SwiftPM package for simulator XCTest
  Sources/
    Core/
      XinstaFeature.h/.m              # inert, adapter-bound feature descriptor
      XinstaFeatureRegistry.h/.m      # adapter-scoped defaults + explicit overrides
      XinstaHostMetadata.h/.m         # injectable bundle metadata value object
      XinstaCompatibility.h/.m        # identity/version/build/target gate
      XinstaSettingsDataSource.h/.m   # Foundation-only settings model
    Adapter/
      XinstaIG456Adapter.h/.m         # 456.0.0-specific read-only checks
      XinstaDiagnostic.h/.m           # fixed-code initialization diagnostic
    UI/
      XinstaSettingsViewController.h/.m  # standalone UIKit settings screen
      XinstaSettingsPresenter.h/.m    # caller-driven, fail-closed presentation
    XinstaCore.h/.m                   # dylib load entry, @autoreleasepool
  Scripts/
    build-dylib.sh                    # unsigned arm64 iOS dylib + strict validation
    run-tests.sh                      # Foundation-only tests on macOS
  Tests/
    XinstaCoreTests.m                 # Foundation assertions for gate and Phase 3 behavior
    XinstaUIKitTests/                 # iOS Simulator XCTest cases
```

Instagram-specific knowledge is confined to `Sources/Adapter/` and the symbol
list in `XinstaCompatibility.m`. Core, settings, and UI modules have no
Instagram imports.

## Evidence (read-only)

The following were observed in the decrypted (`cryptid=0`) arm64 main binary
of the reference IPA, build `1114925422`:

- Bundle identity: `com.burbn.instagram`.
- Class-string evidence: `IGProfileSheetTableViewController` (also present as
  the Swift mangled reference `So33IGProfileSheetTableViewControllerC`).
- UIKit data-source selectors present in `__objc_methname`:
  `tableView:numberOfRowsInSection:`, `tableView:cellForRowAtIndexPath:`,
  `tableView:didSelectRowAtIndexPath:`.
- Settings-related candidates gathered but **not** promoted to hooks:
  `IGSettings2Renderer`, `IGSettings2Service`, `_settingsButtonTapped`.

A string existing in a binary confirms presence, not that a class implements
a selector or that swizzling it is safe. The adapter rechecks every symbol with
`objc_getClass` / `class_getInstanceMethod`. Even a passing check only records
readiness; it does not activate a hook.

See `docs/IG456_STATIC_EVIDENCE.md` for the full DLInsta 3.0.0 / 3.0.2
comparison and the target 456 compatibility matrix. That report uses only
`VERIFIED`, `FAILED`, `BLOCKED`, and `NOT TESTED`: it does not promote selector
strings to hooks or preference APIs to a verified preference-to-hook linkage.

## Build and tests

Local work happens on Windows; compilation and tests run on GitHub macOS
runners with no Apple credentials.

- Workflow: `.github/workflows/xinsta-core-build.yml` (`macos-15`).
- `build-dylib.sh` compiles `libXinstaCore.dylib` for `arm64-apple-ios16.3`,
  unsigned, with `-O2 -Wall -Wextra -Werror` preserved.
- `run-tests.sh` compiles and runs Foundation-only assertions covering feature
  registration, adapter binding, hardened persistence, fresh settings reads,
  compatibility rejection, injected adapter behaviour, runtime symbol lookup,
  initialization diagnostics, and the load entry point.
- A SwiftPM package runs XCTest cases on an unsigned iOS Simulator with
  `CODE_SIGNING_ALLOWED=NO`, covering controller initialisation, footer text,
  row count, cell configuration, toggle persistence, out-of-range safety,
  inherited-initializer rejection, and fail-closed presentation.

### Build evidence

GitHub Actions run `44832109087` (push of
`50124910dc15698e25194b35f82d027e5bd3b7b4`, `macos-15-arm64`, Xcode 16.4 / iOS SDK
18.5) completed successfully:

```
file: Mach-O 64-bit dynamically linked shared library arm64
MH_MAGIC_64    ARM64   ALL  0x00  DYLIB  21  3152  NOUNDEFS DYLDLINK TWOLEVEL NO_REEXPORTED_DYLIBS
cmd LC_BUILD_VERSION
platform 2
minos 16.3
sdk 18.5
@rpath/libXinstaCore.dylib (compatibility version 0.0.0, current version 0.0.0)
Xinsta Core artifact validation passed: unsigned arm64 iOS 16.3 dylib
XinstaCore tests: 58 passed, 0 failed
Xinsta Core artifact verified: unsigned arm64 iOS 16.3 Mach-O dylib
```

These counts are from the earlier core milestone. Phase 3 verification is
recorded separately below.

The simulator step in the same run created
`com.apple.CoreSimulator.SimDeviceType.iPhone-16` on
`com.apple.CoreSimulator.SimRuntime.iOS-26-2`, booted it without signing, and
reported `XinstaSettingsViewControllerTests`: `Executed 5 tests, with 0 failures
(0 unexpected)` followed by `** TEST SUCCEEDED **`. `platform 2` is
`PLATFORM_IOS`. Artifact validation is fail-closed: existence, non-empty size,
64-bit Mach-O type, ARM64 architecture, `MH_DYLIB` filetype, iOS platform,
minimum OS 16.3, absence of `LC_CODE_SIGNATURE`, and the `@rpath` install name
are all checked explicitly with no suppressed failures.

The parallel licensing API suite (run `44832109059`) passed on the same commit.
These runs prove only the unsigned dylib compile, Core tests, simulator XCTests,
and artifact structure — not Instagram integration or device behaviour.

To reproduce locally on macOS:

```bash
bash ios/XinstaCore/Scripts/build-dylib.sh
bash ios/XinstaCore/Scripts/run-tests.sh
cd ios/XinstaCore && xcodebuild test \
  -scheme XinstaCore \
  -sdk iphonesimulator \
  -destination 'platform=iOS Simulator,name=<booted simulator>' \
  CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO CODE_SIGN_IDENTITY=""
```

### Future @rpath strategy

The dylib install name is `@rpath/libXinstaCore.dylib`. That is deliberate but
incomplete: the dylib itself adds no `LC_RPATH`, and this PR adds no host app or
injection step. A future, separately reviewed installer must place the dylib in
the final app bundle (for example `Contents/Frameworks` or `Frameworks`) and
add an `LC_RPATH` to the host executable that resolves to that directory, or
load by an explicit resolved path. `otool -L` validation currently checks the
expected install name only; no loader/rpath behaviour is claimed here.

## Phase 3: static-evidence-driven hardening

This increment responds to the DLInsta/target static evidence without turning
any static observation into a runtime claim.

- **Version-specific capability gate**: `XinstaCompatibility` now exposes the
  single target class (`IGProfileSheetTableViewController`) and the three
  table-view selectors required by the 456.0.0 / build 1114925422 adapter. A
  missing target class produces the separate `target_unavailable` code.
- **Explicit feature-to-adapter binding**: every `XinstaFeature` declares an
  `adapterIdentifier`; `XinstaFeatureRegistry` filters to one binding and
  refuses writes for unbound identifiers. No feature is implicitly available.
- **Fail-closed missing target**: `XinstaIG456Adapter.targetRuntimeVerified`
  becomes YES only from the same accepted evaluation that observed the target
  class. Presentation refuses to run when it is NO.
- **Initialization diagnostic**: the load path emits one fixed-code line with
  status, bound-feature count, and acceptance. It never logs host-controlled
  metadata, preference values, paths, or exception text. The diagnostic itself
  is wrapped so an unexpected exception maps to `invalid_input`.
- **Safe presentation mechanism**: `XinstaSettingsPresenter` is the only
  presentation entry point. It requires main-thread use, an accepted adapter,
  a verified target runtime, a matching binding, and at least one bound
  feature. It does not discover, swizzle, or modify an Instagram view
  controller; a future integration must explicitly supply a validated host
  `UIViewController`.
- **Fresh state reads**: settings cells and the status footer re-read the
  registry and adapter on appearance and after toggles; no feature state is
  cached in the controller.

Phase 3 does **not** add a hook, an injection path, the owner's future feature
catalog, or a claim that X Settings was shown in Instagram.

### Phase 3 verification

GitHub Actions workflow-dispatch run `44854002545` on head
`fbfdc5f2ab18db0233b9d7e0eab34181f5d169d1` completed successfully on
`macos-15`:

- unsigned iOS dylib compilation with strict warnings: passed;
- `XinstaCore tests: 82 passed, 0 failed`;
- `Executed 8 tests, with 0 failures (0 unexpected)` followed by
  `** TEST SUCCEEDED **`;
- `Xinsta Core artifact verified: unsigned arm64 iOS 16.3 Mach-O dylib`.

The local Windows workspace independently verified `301 passed, 30 skipped`
Python tests, `OK (7 tests)` for the legacy licensing suite, synchronized
OpenAPI, and a clean `git diff --check`. These results do not prove Instagram
runtime loading, hooking, presentation inside Instagram, or device behaviour.

### Independent Phase 3 review

A fresh, read-only independent review of head `f1a5dd6` returned
`APPROVE WITH NON-BLOCKING NOTES`: no blocking findings and no claim of runtime
hook behaviour, Instagram-host presentation, or device verification. The
reviewer noted that one runner label and one static-report status label were
inconsistent with the underlying workflow/status taxonomy; both are corrected
on this head. It also noted a defensive diagnostic status that is currently
unreachable through the adapter state machine, and that load-log redaction,
off-main-thread presentation refusal, and presenter binding mismatch are
code-inspected rather than directly asserted. This record is review evidence,
not merge authorization.

### PR #11 status (21 November 2026)

[PR #11](https://github.com/Binz2008-star/Project-X/pull/11) is a separate OPEN
DRAFT for `feature/xinsta-static-integration`, based on
`feature/integration-readiness`. It carries the Phase 3 static evidence and
inert Core diagnostics/settings work, plus the documentation updates recording
the PR chain and owner-directed hold. It adds no hook, injection, signing,
repackaging, installation, device execution, or runtime proof.

The exact-456 class→selector→encoding table and selector-reference analysis are
read-only investigations kept outside the repository. The table is now complete:
52,806 classes, 187,672 method entries and 187,670 unique class/selector/encoding
rows were recovered after resolving `LC_DYLD_CHAINED_FIXUPS`. The results are
recorded in [IG456_STATIC_EVIDENCE.md](IG456_STATIC_EVIDENCE.md), including the
finding that `IGProfileSheetTableViewController` does not directly own the three
required table-view selectors in its own method list. This static prerequisite is
satisfied; it is not hook proof. PRs #7/#9/#10 remain held until the owner's
single vertical-slice hook result is in.

## Model 1 review closure

| Finding | Status | Evidence |
| --- | --- | --- |
| H-1 app identity validation | FIXED | `XinstaHostMetadata.h/.m`, `XinstaCompatibility.m`, adapter tests |
| H-2 adapter/runtime tests | FIXED | injected adapter tests in `XinstaCoreTests.m`; simulator XCTest target in `Package.swift` |
| M-1 `installed` naming | FIXED | renamed to `compatibilityAccepted`; header states it is metadata-only |
| M-2 constructor pool | FIXED | `XinstaCore.m` wraps load in `@autoreleasepool` |
| M-3 persistence hardening | FIXED | `XinstaFeatureRegistry.m` validates dictionary/NSNumber and whitelists identifiers |
| M-4 nullable contract | FIXED | `XinstaSettingsDataSource.h/.m` marks `featureAtIndex:` and report parameter nullable |
| M-5 UI initializers | FIXED | inherited initializers are `NS_UNAVAILABLE` and raise |
| M-6 synchronization | FIXED | adapter uses `NSLock`; registry uses `@synchronized`; no public main-thread-only contract remains |
| M-7 @rpath guidance | FIXED | install name validated; strategy documented above |
| M-8 artifact validation | FIXED | minos, unsigned status, and install name now asserted |
| L-1 wording | FIXED | compatibility header and this document describe read-only gating; exact runs recorded |
| L-2 test hygiene | FIXED | suites removed; malformed/duplicate/nil cases added |
| L-3 UI layout/cells | FIXED | footer uses Auto Layout + `sizeThatFits:`; switches are reused per cell |
| L-4 stable log codes | FIXED | constructor logs `reasonCode`, not host-controlled strings |

## Verified vs unverified

- Verified: read-only symbol and bundle presence in the exact reference IPA;
  unsigned dylib compilation; the Foundation and simulator assertions reported
  in the recorded CI runs; fail-closed artifact structure.
- Unverified and explicitly out of scope here: runtime swizzling, injection
  into a running Instagram process, presentation of X Settings from Instagram
  UI, code signing, device installation, and iPhone 13 behaviour.

## Exact remaining steps before any iPhone 13 testing

1. Obtain written owner authorisation for device testing and for the specific
   enhanced features permitted for this owned app.
2. Retain the completed Model 1 / Phase 3 review records; any new code head requires a fresh review.
3. Add one verified hook in the adapter, with a narrow method replacement on a
   confirmed method, and prove it against a locally installed, owner-owned copy
   of Instagram 456.0.0 — never against a store account.
4. Select an implantation/injection method that does not jailbreak the device
   and is permitted by applicable terms for the owned application.
5. Prepare a private signing identity, matching provisioning profile, and the
   iPhone 13 UDID registered in that team. Keep all of these out of GitHub;
   use secret injection only.
6. Repackage a **copy** of the IPA with the dylib inserted, resolve `@rpath`,
   re-sign the bundle and all frameworks, then install with a personal-device
   tool using the owner's Apple ID.
7. Run the on-device checklist: app launches, original settings unchanged,
   X Settings opens, demo toggle persists, adapter status matches the build,
   no crashes — then capture crash logs and screenshots for review.
8. Only after all of the above and owner approval may a merge or any wider
   distribution be considered.
