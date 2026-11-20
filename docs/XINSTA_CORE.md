# Xinsta Core

Xinsta Core is an iOS-only, modular foundation for authorised enhanced
functionality and an **X Settings** screen. This increment delivers the core
library, a version-gated compatibility adapter for Instagram 456.0.0, an
isolated build, and automated tests. It does **not** modify, package, sign, or
install any Instagram application, and it performs **no method swizzling**.

## Scope and safety

- iOS only. Minimum deployment target: iOS 16.3 (matches the analysed IPA).
- No Android, no jailbreak, no storefront, no payment.
- The reference IPA (`F:\Instagram.ipa`, owner-provided) was read only through
  the protected `SafeArchive` tooling. No IPA binary, extracted payload,
  certificate, or provisioning profile is stored in this repository.
- The adapter fails closed: if the app version, build, or any required runtime
  symbol does not match, it leaves every Instagram class untouched.

## Layout

```
ios/XinstaCore/
  Sources/
    Core/
      XinstaFeature.h/.m          # inert feature descriptor
      XinstaFeatureRegistry.h/.m  # defaults + explicit user overrides
      XinstaCompatibility.h/.m    # version/build/symbol gate
      XinstaSettingsDataSource.h/.m  # Foundation-only settings model
    Adapter/
      XinstaIG456Adapter.h/.m     # 456.0.0-specific read-only checks
    UI/
      XinstaSettingsViewController.h/.m  # UIKit settings screen
    XinstaCore.m                  # dylib constructor, logs compatibility only
  Scripts/
    build-dylib.sh                # unsigned arm64 iOS dylib
    run-tests.sh                  # Foundation-only tests on macOS
  Tests/
    XinstaCoreTests.m
```

Instagram-specific knowledge is confined to `Sources/Adapter/` and the symbol
list in `XinstaCompatibility.m`. Core, settings, and UI modules have no
Instagram imports.

## Evidence (read-only)

The following were observed in the decrypted (`cryptid=0`) arm64 main binary
of the reference IPA, build `1114925422`:

- Class-string evidence: `IGProfileSheetTableViewController` (also present as
  the Swift mangled reference `So33IGProfileSheetTableViewControllerC`).
- UIKit data-source selectors present in `__objc_methname`:
  `tableView:numberOfRowsInSection:`, `tableView:cellForRowAtIndexPath:`,
  `tableView:didSelectRowAtIndexPath:`.
- Settings-related candidates gathered but **not** promoted to hooks:
  `IGSettings2Renderer`, `IGSettings2Service`, `_settingsButtonTapped`.

A string existing in a binary confirms presence, not that a class implements
a selector or that swizzling it is safe. The adapter therefore rechecks every
symbol with `objc_getClass` / `class_getInstanceMethod` at load time, and even
a passing check only enables the "Ready" status text — it does not activate a
hook.

## Build and tests

Local work happens on Windows; compilation and tests run on GitHub macOS
runners with no Apple credentials.

- Workflow: `.github/workflows/xinsta-core-build.yml` (`macos-15`).
- `build-dylib.sh` compiles `libXinstaCore.dylib` for `arm64-apple-ios16.3`,
  unsigned, and verifies the Mach-O header.
- `run-tests.sh` compiles and runs 17 Foundation-only assertions covering
  feature registration, settings persistence/toggles, and compatibility
  fail-closed behaviour.

To reproduce locally on macOS:

```bash
bash ios/XinstaCore/Scripts/build-dylib.sh
bash ios/XinstaCore/Scripts/run-tests.sh
```

## Verified vs unverified

- Verified: read-only symbol presence in the exact reference IPA; unsigned
  dylib compilation and Core tests on macOS (see workflow run evidence once
  the branch is pushed).
- Unverified and explicitly out of scope here: runtime swizzling, injection
  into a running Instagram process, presentation of X Settings from Instagram
  UI, device installation, and iPhone 13 behaviour.

## Exact remaining steps before any iPhone 13 testing

1. Obtain written owner authorisation for device testing and for the specific
   enhanced features permitted for this owned app.
2. Complete an independent review of this core (requested as Model 1 review).
3. Add one verified hook in the adapter, with a narrow swizzle of a confirmed
   method, and prove it against a locally installed, owner-owned copy of
   Instagram 456.0.0 — never against a store account.
4. Select an implantation/injection method that does not jailbreak the device
   and is permitted by applicable terms for the owned application.
5. Prepare a private signing identity, matching provisioning profile, and the
   iPhone 13 UDID registered in that team. Keep all of these out of GitHub;
   use secret injection only.
6. Repackage a **copy** of the IPA with the dylib inserted, re-sign the bundle
   and all frameworks, then install with a personal-device tool (e.g.
   AltStore/Sideloadly) using the owner's Apple ID.
7. Run the on-device checklist: app launches, original settings unchanged,
   X Settings opens, demo toggle persists, adapter status matches the build,
   no crashes — then capture crash logs and screenshots for review.
8. Only after all of the above and owner approval may a merge or any wider
   distribution be considered.
