# Instagram 456 private-pilot identity policy

Status: **DEVELOPMENT POLICY + DRY-RUN PLANNER; NOT TESTED ON A DEVICE**. No IPA
has been signed, injected, repackaged, installed, launched, or modified. No
iPhone was changed. Core source and the unsigned dylib are CI-verified at the
recorded head; this document is still a review artifact, not an execution permit.

The private pilot is a separate, development-only application identity derived
from the exact owner-provided Instagram `456.0.0` source artifact. Its purpose is
to test whether an independently signed copy can coexist with the already
installed production app and load Xinsta Core without touching the production
data container. It is not a storefront, a redistribution path, a production
adapter relaxation, or a hook plan.

## Classification rules

| Status | Meaning |
| --- | --- |
| `VERIFIED` | Directly observed in local code, tests, static artifact bytes, or host inventory. |
| `FAILED` | Checked and contradicted by available evidence. |
| `BLOCKED` | Requires explicit owner authorization, secure signing inputs, or an independent review. |
| `NOT TESTED` | Requires an authorized runtime/device environment that has not been provided. |

## Pinned identities

| Field | Production reference | Private pilot |
| --- | --- | --- |
| Bundle identifier | `com.burbn.instagram` | `com.projectx.xinsta.pilot` |
| Display name | `Instagram` | `Xinsta` |
| Version | `456.0.0` | `456.0.0` |
| Build | `1114925422` | `1114925422` |
| Adapter binding | `com.burbn.instagram@456.0.0@1114925422` | `com.projectx.xinsta.pilot@456.0.0@1114925422` |
| Source SHA-256 | `665a814e13d8c187dce5a78d0e8348f73f9081205b927291d7d5d2bce96eb131` | identical source, distinct output artifact required |
| Output artifact SHA-256 | not applicable | declaration-bound; must differ from the source hash |
| URL scheme | unchanged production schemes | exactly `xinsta-pilot-loadproof` |
| App Groups | none recorded in the source IPA | `group.com.projectx.xinsta.pilot` prefix only |
| Keychain groups | none recorded in the source IPA | no custom keychain groups |
| Extension identifiers | `com.burbn.instagram.*` | `com.projectx.xinsta.pilot.` prefix |
| Minimum iOS | `16.3` | `16.3` |

The source IPA hash is the exact hash recorded in
`docs/IG456_STATIC_EVIDENCE.md`. The target executable hash is
`4fb7ae5c16c91e77104bdc173c173df9d09a8e0a92ce356d558ffefcf9253378`.
These values are static evidence only; they do not authorize installation.

The read-only analyzer on the pinned source reports **8** URL schemes and **8**
embedded extensions. Every one of the eight production extension identifiers
must be rewritten to the pilot prefix. Earlier notes that counted seven
extensions were imprecise; the current analyzer inventory is the controlling
evidence for the packaging planner.

## Core identity policy

`XinstaIdentityPolicy` maps exactly two host identities to exactly two adapter
bindings:

1. production `com.burbn.instagram` / `456.0.0` / `1114925422` maps to the
   unchanged production adapter identifier;
2. pilot `com.projectx.xinsta.pilot` / `456.0.0` / `1114925422` maps to the
   pilot adapter identifier.

Every other combination returns no binding. The compatibility gate accepts only
those exact identities plus the required runtime symbols. The production class
binding remains static and unchanged; the accepted adapter instance carries the
resolved binding. Feature registries are per binding, and the diagnostic reports
`binding_mismatch` if a production adapter is paired with a pilot registry or
vice versa. No hook, swizzle, method replacement, or host class modification is
implemented or enabled.

Status of the Objective-C policy source at committed head
`1c6395e42890be0d65c6f6a5099c3b0c6158fd64`: `VERIFIED` by macOS CI run
`44909181721` — 114 Foundation assertions passed, 8 simulator XCTests passed,
and the unsigned arm64 iOS 16.3 dylib passed structural verification. The
production gate remains unchanged for all non-pilot identities: `NOT TESTED` in
a real host, `VERIFIED` as source/test intent in this repository.

## Dry-run packaging planner

`scripts/pilot_package_plan.py` turns the pinned evidence into a deterministic,
read-only plan. It verifies the source hash and identity, verifies the dylib is
the unsigned arm64 iOS 16.3 artifact with install name
`@rpath/libXinstaCore.dylib` and system-only dependencies, then emits planned
package changes with all signing, repackaging, analysis-on-output and device
steps marked `blocked`. It never extracts, edits, signs, writes or installs an
IPA. Its `execution_permitted` field is always `false`.

```powershell
.\.venv\Scripts\python.exe -m scripts.pilot_package_plan `
  --ipa F:\Instagram.ipa `
  --dylib <downloaded-unsigned-libXinstaCore.dylib>
```

Verified against the pinned source and the downloaded CI artifact:
`source.sha256` equals the pinned Instagram hash, `source.extension_count = 8`,
`source.url_scheme_count = 8`, `source.main_executable_rpaths` is exactly
`@executable_path/Frameworks`, `source.core_load_command_present = false`,
all 14 nested bundles have signature metadata with none unsigned, no source App
Groups, Keychain groups or associated-domains entitlement are declared, and no
signature-verification claim is made. `dylib.sha256` equals
`bf58dd04ca747d2d489c92509c9b8e96e2946197ee868c3245fbf5a50a0accff`,
`dylib.load_command_count = 21`, `dylib.dependencies = system_only`, and
`dylib.signed = false`. The pinned `pilot_identity.display_name` is `Xinsta`,
and the rpath step is marked `already_present` rather than proposing a duplicate
load command. The output contains no paths, timestamps, secrets or device
identifiers.

## Build Manager policy

The read-only Build Manager accepts a third rights basis,
`private-pilot-installability`, only when a complete `private_pilot` declaration
is present. It fails closed when:

- the source hash is not the exact pinned Instagram IPA hash;
- the pilot artifact hash equals the source hash;
- the bundle, display name, version, build, adapter identifier, or rights basis is not pinned;
- `replace_existing_app` is not `false` or `preserve_original_data` is not `true`;
- URL schemes, App Groups, Keychain groups, extension identifiers, or profile
  entitlements differ from the pilot declaration;
- the inspected package claims signature verification or a malware verdict; or
- the report schema is not `1.0`, `1.1`, or `1.2`.

A successful build-manager result produces only a dry-run plan:
`execution_permitted = false`, `hook = false`, `swizzle = false`, and blocked
signing, device-registration, isolation, and load-proof steps. The plan does not
prove coexistence and does not execute anything.

## Coexistence design

The pilot uses a different bundle identifier, a separate URL scheme, a pilot-only
App Group prefix, no custom Keychain groups, and pilot-only extension
identifiers. It does not reference the production App Group, Keychain group, or
extension identifiers. The original IPA and any installed production app are
never overwritten by repository code.

These design choices are necessary for coexistence, but they are not evidence of
on-device coexistence. The following remain `NOT TESTED`: two installed apps at
once, separate data containers, launch isolation, and an unchanged production
app after pilot installation and removal. On-device confirmation is a blocked
step in the dry-run plan.

## Windows host investigation

An earlier session observed Apple USB/WPD nodes with status `OK`. That is
historical evidence only. A fresh read-only check in this execution phase found
the device is **not currently readable from Windows**:

| Observation | Result |
| --- | --- |
| Apple Mobile Device Service | running, automatic start — `VERIFIED` |
| iTunes COM version | `12.13.10.3` — `VERIFIED` |
| iTunes COM device count | `0` — `VERIFIED` |
| Present-only Apple PnP devices | `0` — `VERIFIED` |
| Windows trust/data-mode access | `NOT TESTED` because no device is currently readable |
| iOS version | `NOT TESTED` — no readable device |
| Pairing validity | `NOT TESTED` — no readable device |
| Developer Mode state | `NOT TESTED` — no Windows read-only path available |

The following were checked without printing a UDID, serial, Apple ID, or personal
device name:

| Item | Status |
| --- | --- |
| Sideloadly installed or run | `FAILED` — not installed on this Windows host |
| `xcodebuild`, `clang`, `make`, `ruby`, `pod`, Theos | absent on Windows host |
| `codesign`, `ios-deploy`, `idevice_id`, `idevicedevmodectl` | absent on Windows host |
| Code-signing certificate with code-signing EKU | `FAILED` — none found |
| Provisioning profile files | `FAILED` — none found |
| Installable injected/repacked IPA | `NOT TESTED` |

Windows USB visibility alone is not a signing capability. The macOS build path
remains the reviewed way to produce the unsigned dylib. Sideloadly is not
installed here, so it cannot complete the flow in the current host state; it
would still require an independent review of the exact tool build, signing
inputs, profile, and uninstall path. macOS tooling is not strictly required for
the *idea* of a Windows installation, but no approved Windows installer path is
currently available. A macOS host with `ios-deploy` and a valid development
profile remains the reviewed candidate; it is `BLOCKED` pending owner-approved
signing inputs and device scope.

## Candidate final installation procedure

Every step below is `BLOCKED` until an independent reviewer approves the exact
source head, the signed artifact, the signing inputs, the rollback plan, and the
owner's device scope. Do not run these steps from repository code. Run them only
on a private host with mode `0700` work and evidence directories.

1. Record the clean reviewed checkout, exact commit, source status, and tool
   versions in private evidence. Stop if the tree is dirty or the head differs
   from the approved head.
2. Verify the original IPA hash and `Info.plist` identity against the pinned
   table. Stop on any mismatch. Do not substitute another IPA.
3. Build the unsigned dylib with `ios/XinstaCore/Scripts/build-dylib.sh` on the
   reviewed macOS runner. Run `ios/XinstaCore/Scripts/run-tests.sh`. Record the
   dylib hash and full build/test output privately.
4. Unpack the IPA only under the private work directory. Rewrite the disposable
   app copy to the pilot identity: bundle ID, display name, single pilot URL
   scheme, pilot extension bundle IDs, pilot App Group prefix, and no custom
   Keychain groups. Do not alter the original archive.
5. Stage `libXinstaCore.dylib` under the copy’s `Frameworks` directory, insert
   the `@rpath/libXinstaCore.dylib` load command, and add the
   `@executable_path/Frameworks` rpath. Verify both with `otool` and save only
   the fixed evidence lines privately.
6. Sign the dylib, nested bundles, extensions, and app with a pilot development
   profile whose entitlements match the declaration. Run local structural
   `codesign --verify --strict`; a local structural check is not Apple approval.
7. Repackage into a distinct pilot IPA. Run the read-only analyzer on the result
   and pass its real report plus the pilot declaration to the Build Manager.
   Stop if any blocker appears or if the plan is not dry-run-only.
8. Confirm the iPhone’s iOS version and Developer Mode state through an approved
   read-only path before installation. Both are still `NOT TESTED` here.
9. Install the pilot with the independently approved installer. If the macOS
   `ios-deploy` path is chosen, follow the already-reviewed
   `docs/IG456_LOAD_PROOF_RUNBOOK.md` controls with the pilot identity values.
   The Windows/Sideloadly path is `NOT TESTED` and needs separate approval.
10. Launch the pilot once. Do not log in, toggle a feature, present X Settings,
    or exercise Facebook/Instagram account behavior. Capture a private console
    line containing the pilot process name and the fixed marker
    `[XinstaCore] init=`. Record the exact emitted code only.
11. Verify the production app is still installed and that no production data was
    opened or changed by the pilot flow. If this cannot be verified, record
    `NOT TESTED`; do not claim coexistence.
12. Remove the pilot using the rollback steps below. Only after a redacted
    evidence summary and independent review may the result be reported.

## Evidence required before `VERIFIED`

All of the following must exist in the private evidence bundle:

1. exact clean source head and approved review reference;
2. original source hash and pinned identity values, including all 8 extensions;
3. macOS CI build/test logs and unsigned dylib hash;
4. dry-run packaging planner output for the exact source and dylib;
5. pilot output hash distinct from the source hash;
6. analyzer report and dry-run Build Manager result with no blockers;
7. load-command and rpath evidence lines;
8. local signing verification output with no errors;
9. iOS version and Developer Mode state, recorded without UDID or private logs;
10. installer output for the pilot bundle only;
11. a console line containing the pilot process name and `[XinstaCore] init=`;
12. post-install confirmation that the production app remains installed;
13. post-rollback confirmation that the pilot is gone and production remains.

The marker proves only that the constructor ran. A `ready` code proves that the
read-only gate accepted the pilot host. Neither proves a hook, X Settings
presentation, feature behavior, account use, or data-container isolation.

## Rollback plan

| Step | Action | Status |
| --- | --- | --- |
| 1 | Stop the pilot process and end private console capture. | `BLOCKED` until runtime scope is approved. |
| 2 | Uninstall only `com.projectx.xinsta.pilot` using the same approved installer’s uninstall path. | `BLOCKED`; exact Sideloadly removal is `NOT TESTED`. |
| 3 | Confirm the production bundle `com.burbn.instagram` is still present using a read-only app inventory. | `NOT TESTED`. |
| 4 | Do not delete, reset, or restore the production app data container. | Required control. |
| 5 | If the production app is absent or damaged, stop immediately and seek owner approval; do not attempt an unsupervised restore. | Required control. |
| 6 | Keep only a redacted evidence summary in the repository. Never commit the IPA, certificate, profile, UDID, Apple ID, raw syslog, or private paths. | Required control. |

## Explicitly out of scope

Production-gate relaxation, hooks, swizzles, X Settings presentation, preference
to implementation linkage, account login, feature behavior, storefront, paywall,
redistribution, merge to `main`, deployment, and any change to the installed
Instagram app remain `BLOCKED` or `NOT TESTED`.
