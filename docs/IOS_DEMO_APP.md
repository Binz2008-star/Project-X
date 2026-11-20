# iOS demo app — owned, unsigned build verification

Status: **unsigned compilation verified on GitHub Actions.** This is a demonstration application owned by Project X. It is not derived from, repackaged from, or compatible with any third-party IPA. Runtime behaviour on a simulator or physical device has not been tested.

## 1. What this proves and what it does not

The app proves that an owned SwiftUI iOS application with an **X Settings** menu and a **modular feature registry** compiles from source on a GitHub Actions macOS/Xcode runner without any Apple Developer credentials.

It does **not** prove:

- that the app is installable on a physical iPhone (that requires signing),
- that any tweak, injection, framework or third-party IPA works,
- that a signature is valid — the CI build is unsigned,
- that runtime behaviour on iOS is correct; no simulator or device launch is performed.

No Instagram IPA was read, modified or repackaged for this task. No certificate, provisioning profile, signed IPA or compiled `.app` is stored in the public repository.

## 2. App structure

```
ios/DemoApp/
  DemoApp.xcodeproj/
    project.pbxproj
    xcshareddata/xcschemes/DemoApp.xcscheme
  Sources/
    DemoAppApp.swift       @main entry point, owns FeatureStore
    FeatureRegistry.swift  FeatureModule protocol, registry, persisted store
    ContentView.swift      root list, X Settings link, feature toggles
    XSettingsView.swift    X Settings screen
```

### X Settings menu

The root screen contains a navigation link labelled **X Settings**. That screen shows app identity, the current state of every registered feature, and an explicit note that the binary is unsigned. No network access, analytics or device modification occurs.

### Modular feature registry

`FeatureModule` is a small protocol (`id`, `title`, `summary`, `isEnabledByDefault`). `FeatureRegistry.modules` is the single place where features are declared; adding a module automatically adds it to the settings list and to `UserDefaults`-backed persistence via `FeatureStore`. The bundled modules are `diagnostics`, `appearance` and `localOptions` — all owned, inert demonstration flags.

Bundle identifier: `com.projectx.demo`. Deployment target: iOS 16.0. Devices: iPhone and iPad. Swift 5.0, SwiftUI, no third-party dependencies.

## 3. Windows-first development model

The owner's PC runs Windows and has no Xcode. Therefore:

1. Swift sources and the Xcode project are edited on Windows and committed.
2. Pushing to `feature/**` or `main` with changes under `ios/**` triggers the **isolated** workflow `.github/workflows/ios-demo-build.yml`.
3. A macOS runner executes `xcodebuild` for the iOS Simulator SDK with signing disabled, verifies the generated `DemoApp.app`, reads `Info.plist` and records a SHA-256 in the build log.
4. The licensing backend workflow `ci.yml` is unchanged; the two workflows have separate names, triggers and jobs.

The workflow uses no secrets, no Apple ID, no team ID and no provisioning profile. It can be triggered manually with `workflow_dispatch` as well.

To reproduce locally on a Mac:

```bash
xcodebuild \
  -project ios/DemoApp/DemoApp.xcodeproj \
  -scheme DemoApp \
  -configuration Debug \
  -sdk iphonesimulator \
  -destination 'generic/platform=iOS Simulator' \
  -derivedDataPath /tmp/DemoAppDerivedData \
  CODE_SIGNING_ALLOWED=NO \
  build
```

## 4. Compilation evidence

Recorded from GitHub Actions run [`44808594836`](https://github.com/Binz2008-star/Project-X/actions/runs/44808594836) on `feature/ios-demo-app` at 2026-11-20T20:08Z:

- Workflow: `iOS demo app — unsigned macOS build verification`
- Runner: `macos-15`
- Xcode: **16.4** (`xcodebuild -version`)
- Build command: `xcodebuild -project ios/DemoApp/DemoApp.xcodeproj -scheme DemoApp -configuration Debug -sdk iphonesimulator -destination 'generic/platform=iOS Simulator' -derivedDataPath … CODE_SIGNING_ALLOWED=NO CODE_SIGN_IDENTITY= PROVISIONING_PROFILE_SPECIFIER= build`
- Result: **BUILD SUCCEEDED** (log line: `** BUILD SUCCEEDED **`).
- Generated binary: `DemoApp.app/DemoApp`, `Mach-O 64-bit executable arm64`
- Verified `CFBundleIdentifier`: **com.projectx.demo**
- Verified `MinimumOSVersion`: **16.0**
- SHA-256 of `DemoApp.app/DemoApp`: **b9e07752c246dffbe76708ce59311d13a573c78f744e14a5825276774da551d8**
- Build log: one informational tool warning, `Metadata extraction skipped. No AppIntents.framework dependency found.` No compiler error or Swift warning was recorded.

This proves compilation only. The workflow did not launch a simulator or install the app on a device. An earlier run using the retired `macos-14` label was cancelled before any step ran; the workflow now uses the supported `macos-15` label.

## 5. Exact requirements for a future physical-iPhone test

A simulator build cannot be installed on an iPhone. Signing must happen on a Mac with Xcode, using an identity that is never committed to this repository.

### Option A — free Apple ID, direct Xcode install (lowest friction)

1. A macOS host with Xcode 15 or newer.
2. Sign in with an Apple ID in Xcode; choose **Personal Team** for the target.
3. Connect the iPhone 13 by USB and trust the computer when prompted.
4. On the phone: **Settings → Privacy & Security → Developer Mode → Enable**, then restart and confirm. Required for developer-signed apps on modern iOS.
5. In Xcode, select the connected device as the run destination and press Run. Xcode creates a development certificate and provisioning profile locally (in the keychain and Xcode account data, **not** in Git).
6. The installed app is valid for roughly **7 days** with a free account and must be rebuilt/reinstalled after expiry.
7. Change `PRODUCT_BUNDLE_IDENTIFIER` to a globally unique value owned by the owner before this step; `com.projectx.demo` may already be in use by another developer.

### Option B — paid Apple Developer Program

1. Active Apple Developer Program membership.
2. An App ID whose bundle ID matches the app's `PRODUCT_BUNDLE_IDENTIFIER`.
3. The iPhone's UDID registered in the account (for development/ad-hoc profiles).
4. A development or distribution certificate in the Mac keychain, with the private key protected there.
5. A matching **Development** or **Ad Hoc** provisioning profile containing the registered device.
6. `xcodebuild archive` followed by export with an `exportOptions.plist` whose method is `development` or `ad-hoc`; install via Xcode, Apple Configurator or the Apple Devices app.
7. Development builds last up to one year; ad-hoc builds remain installable until the certificate/profile expires, but require re-signing after adding new devices.

### Option C — TestFlight (no jailbreak, no UDID registration)

Requires a paid membership and an App Store Connect record. Archive and upload the build, then install through the TestFlight app on the iPhone. Beta builds expire after 90 days. This avoids ad-hoc profile management but is a distribution workflow and is not part of the current scope.

## 6. How the owner tests a signed build on iPhone 13 without jailbreak

1. Use Option A above for the first proof: Xcode signs automatically and installs directly over USB. No jailbreak, no third-party installer and no IPA file are required.
2. Enable Developer Mode on the device and approve the developer certificate under **Settings → General → VPN & Device Management** if prompted.
3. Verify in the app that **X Settings** opens, that the three registry entries appear, and that toggling a feature persists after relaunch.
4. For a Safari-based OTA install, a signed IPA plus an HTTPS manifest and a distribution profile with the device UDID would be required. That is a later increment and is not implemented here.

Collecting a UDID does not by itself authorise installation; the profile, certificate and explicit device registration must all agree.

## 7. Blocker summary

- No macOS host or Xcode is available in the owner's Windows environment; compilation is delegated to GitHub Actions.
- No authorised signing identity, Team ID, registered UDID or provisioned device is available in this increment.
- Physical-device validation has not been performed and requires explicit owner authorisation.
- The unsigned CI artifact is not installable and must never be described as a working iPhone app.
