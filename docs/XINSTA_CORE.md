# Xinsta Core

Xinsta Core is an iOS-only, modular foundation for authorised enhanced
functionality and an **X Settings** screen. This increment delivers the core
library, a fail-closed compatibility adapter for the Instagram 456.0.0 reference,
an isolated build, and automated tests. It does **not** modify, package, sign, or
install any Instagram application, and it performs **no method swizzling**.

## Scope and safety

- iOS only. Minimum deployment target: iOS 16.3 (matches the analysed IPA).
- No Android, no jailbreak, no storefront, no payment.
- The reference IPA (`F:\Instagram.ipa`, owner-provided) was read only through
  the protected `SafeArchive` tooling. No IPA binary, extracted payload,
  certificate, or provisioning profile is stored in this repository.
- The adapter is metadata-only. It rejects a host unless **all** of the
  following match: bundle identifier `com.burbn.instagram`, version `456.0.0`,
  build `1114925422`, and runtime visibility of every required Objective-C name.
  A pass changes only a status value; it does not modify any Instagram class.
- `compatibilityAccepted == YES` means “the exact host metadata and symbols
  were observed”. It does **not** mean Instagram was hooked, a tweak was
  injected, or X Settings was shown inside Instagram.

## Layout

```
ios/XinstaCore/
  Package.swift                       # minimal SwiftPM package for simulator XCTest
  Sources/
    Core/
      XinstaFeature.h/.m              # inert feature descriptor
      XinstaFeatureRegistry.h/.m      # validated defaults + explicit overrides
      XinstaHostMetadata.h/.m         # injectable bundle metadata value object
      XinstaCompatibility.h/.m        # identity/version/build/symbol gate
      XinstaSettingsDataSource.h/.m   # Foundation-only settings model
    Adapter/
      XinstaIG456Adapter.h/.m         # 456.0.0-specific read-only checks
    UI/
      XinstaSettingsViewController.h/.m  # standalone UIKit settings screen
    XinstaCore.h/.m                   # dylib load entry, @autoreleasepool
  Scripts/
    build-dylib.sh                    # unsigned arm64 iOS dylib + strict validation
    run-tests.sh                      # Foundation-only tests on macOS
  Tests/
    XinstaCoreTests.m                 # 58 Foundation assertions
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

## Build and tests

Local work happens on Windows; compilation and tests run on GitHub macOS
runners with no Apple credentials.

- Workflow: `.github/workflows/xinsta-core-build.yml` (`macos-15`).
- `build-dylib.sh` compiles `libXinstaCore.dylib` for `arm64-apple-ios16.3`,
  unsigned, with `-O2 -Wall -Wextra -Werror` preserved.
- `run-tests.sh` compiles and runs 58 Foundation-only assertions covering
  feature registration, hardened persistence, settings behaviour, compatibility
  rejection, injected adapter behaviour, and runtime symbol lookup.
- A SwiftPM package runs XCTest cases on an unsigned iOS Simulator with
  `CODE_SIGNING_ALLOWED=NO`, covering controller initialisation, footer text,
  row count, cell configuration, toggle persistence, out-of-range safety, and
  inherited-initializer rejection.

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
  unsigned dylib compilation; 58 Foundation assertions; iOS Simulator UIKit
  XCTests; fail-closed artifact structure.
- Unverified and explicitly out of scope here: runtime swizzling, injection
  into a running Instagram process, presentation of X Settings from Instagram
  UI, code signing, device installation, and iPhone 13 behaviour.

## Exact remaining steps before any iPhone 13 testing

1. Obtain written owner authorisation for device testing and for the specific
   enhanced features permitted for this owned app.
2. Complete Model 1 re-review of this core.
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
