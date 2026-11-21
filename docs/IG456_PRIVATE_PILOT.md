# Instagram 456 private-pilot identity policy

Status: **DEVELOPMENT POLICY + DRY-RUN PLANNER + BOUNDED UNSIGNED EXECUTOR; NOT
TESTED ON A DEVICE**. No real third-party IPA has been signed, injected,
repackaged, installed, launched, or modified outside synthetic tests. No iPhone
was changed. Core source and the unsigned dylib are CI-verified at the recorded
head; this document is still a review artifact, not an execution permit.

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

Status of the Objective-C policy source: `VERIFIED` at its last macOS-CI-tested
source commit `1c6395e42890be0d65c6f6a5099c3b0c6158fd64` by run `44909181721`
— 114 Foundation assertions passed, 8 simulator XCTests passed, and the unsigned
arm64 iOS 16.3 dylib passed structural verification. The branch was rebuilt at
`1108a38f1a7beec4fc588b509cfa9b558cd236cf` in run `44911332215` with the same
Objective-C source: 114 Foundation assertions, 8 simulator XCTests and artifact
verification passed again. No Objective-C source has changed in later
planner/docs commits. The production gate remains unchanged for all non-pilot
identities: `NOT TESTED` in a real host, `VERIFIED` as source/test intent in
this repository.

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
signature-verification claim is made. The planner now pins the dylib itself to
`PRIVATE_PILOT_DYLIB_SHA256 =
bf58dd04ca747d2d489c92509c9b8e96e2946197ee868c3245fbf5a50a0accff` and rejects a
different hash with `DYLIB_HASH_MISMATCH`; it also rejects duplicate Core rpath
commands and any Core load-command kind, not just `LC_LOAD_DYLIB`.
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

## Windows/Sideloadly preparation check — fresh read-only pass

This pass did not install or launch Sideloadly, sign, repackage, install, or touch
a device. At the verified code head `3c38ca9` and current branch, read-only checks
found:

| Check | Result |
| --- | --- |
| Sideloadly command on PATH | `FAILED` — not found |
| Sideloadly standard install directories | `FAILED` — none present |
| Sideloadly registry entries, shortcuts, running processes | `FAILED` — none found |
| CI at docs head `cabbaf7` | `VERIFIED` green: API run `44914146320`, macOS run `44914146303` |
| Source IPA hash | `VERIFIED`: `665a814e13d8c187dce5a78d0e8348f73f9081205b927291d7d5d2bce96eb131` |
| Core artifact hash | `VERIFIED`: `bf58dd04ca747d2d489c92509c9b8e96e2946197ee868c3245fbf5a50a0accff` |
| Dry-run planner | `VERIFIED`: `execution_permitted=false`; all four signing/repackage/install steps blocked |
| Packaging pipeline output | `PARTIAL`: bounded unsigned executor implemented and locally tested; signed/installable output remains `BLOCKED` pending rights evidence, nested signing, Sideloadly/device inputs |
| iPhone visibility | `BLOCKED`: iTunes device count `0`; no present Apple USB device; iOS/Developer Mode `NOT TESTED` |
| Signing inputs | `BLOCKED`: `0` code-signing certificates, `0` provisioning profiles, `0` iOS deployment/signing tools found |

Sideloadly is therefore **not installed on this Windows host** and cannot be used
in the current state. Installing it, supplying an Apple signing identity, and
connecting the iPhone require explicit owner approval and must not be done from
repository code. Never paste an Apple ID, app-specific password, UDID,
certificate, profile, or private device log into the repository or chat.

### Shortest practical plan for `Xinsta.ipa`

This is a gated plan, not an execution permit:

1. **Owner gate:** approve the exact code head, the separate pilot identity, the
   registered private device, and the Sideloadly version/source. Supply signing
   inputs through a secrets manager, never in chat or the repository.
2. **Host gate:** install and review Sideloadly on an owner-controlled Windows
   host; connect and trust the iPhone read-only; confirm iOS 16.3+ and Developer
   Mode through an approved path; record the result without UDID or Apple ID.
3. **Inputs:** keep the pinned source IPA and the exact CI dylib artifact;
   reverify both hashes and rerun the dry-run planner. Stop unless
   `execution_permitted=false` and all execution steps remain blocked.
4. **Build the unsigned copy:** on the reviewed host, make a disposable copy
   of the source IPA. Rewrite the 8 extension identifiers, bundle ID, display
   name, URL schemes, App Group prefix, and entitlements to the pinned pilot
   values. Stage the dylib in `Frameworks`; insert the Core load command only if
   absent; do not add a duplicate rpath. Never modify the original IPA. The
   bounded executor implements this file work for an authorized source and stops
   before signing.
5. **Sign:** sign the dylib, nested bundles/extensions, and app with the pilot
   development profile. Sideloadly may perform final signing, but all nested
   bundles must be re-signed and entitlements must match the pilot declaration.
6. **Analyze:** repackage into a distinct `Xinsta.ipa`; run the read-only analyzer
   and Build Manager on the real output. Stop on any blocker; keep the plan
   dry-run-only.
7. **Device test:** install only the pilot alongside production; launch once;
   capture only the pilot process name and `[XinstaCore] init=`; do not log in or
   exercise features; confirm the production app remains installed; then
   uninstall the pilot using the approved Sideloadly removal path.

Current status: steps 1–3 are `VERIFIED`/`BLOCKED` as noted above; steps 4–7 are
`BLOCKED`/`NOT TESTED`. No installable `Xinsta.ipa` exists yet.

## Build execution gate — 21 November 2026

The requested move from planning to a real `Xinsta.ipa` was attempted only as far
as authorized read-only verification. **No installable IPA was produced**, no
output path or hash exists, and no host software was installed.

| Area | Finding |
| --- | --- |
| Repository | `VERIFIED`: clean HEAD `b5dd8fb83196eaee6c96b8a174268694c61e9a22`, `0/0` upstream; CI green at that head (`44914908466`, `44914908475`) |
| Source IPA | `VERIFIED`: pinned hash `665a814e13d8c187dce5a78d0e8348f73f9081205b927291d7d5d2bce96eb131`, `com.burbn.instagram`, `456.0.0` (`1114925422`), min iOS 16.3, arm64, encrypted `0`, 8 extensions, 8 URL schemes, 6 frameworks, 9 resource bundles |
| Core artifact | `VERIFIED`: unsigned arm64 iOS 16.3 dylib hash `bf58dd04ca747d2d489c92509c9b8e96e2946197ee868c3245fbf5a50a0accff`, install name `@rpath/libXinstaCore.dylib`, system-only dependencies |
| Pilot identity | `VERIFIED`: `com.projectx.xinsta.pilot`, display name `Xinsta`, adapter `com.projectx.xinsta.pilot@456.0.0@1114925422`, pilot URL scheme and extension/App Group prefixes pinned |
| Build implementation | `PARTIAL`: `project_x/packaging/builder.py` and `macho_patch.py` implement bounded unsigned copy/identity rewrite/dylib staging/load-command insertion with source-integrity and fail-closed checks. Nested re-signing, final signed packaging, Sideloadly integration, and device execution remain absent |
| Test coverage | `VERIFIED`: 21 builder/planner tests cover unsigned output, source integrity, rights-reference rejection, path-safe CLI errors, Mach-O offset relocation, fileset rejection, and the dry-run planner. Local full suite `366 passed, 30 skipped`; legacy licensing `OK (7 tests)`; OpenAPI synchronized |
| Core runtime behavior | `VERIFIED`: a constructor emits `[XinstaCore] init=...`, evaluates the compatibility gate, builds a feature registry, and can construct X Settings UI objects. No swizzling, method replacement, hooking, or host-class modification is implemented. Device load remains `NOT TESTED` |
| Rights | `BLOCKED`: `AGENTS.md` forbids unlicensed Instagram IPA modification; `docs/RIGHTS_REGISTER.md` records only a scoped private load-only proof and no original-app modification right. Chat approval for a personal test is not a license from the rights holder |
| Windows/Sideloadly | `BLOCKED`: Sideloadly absent; `winget` absent; AMD64 host; web iTunes `12.13.10.3` and Apple Mobile Device Service present; no Microsoft Store iTunes/iCloud packages found; no device, cert, profile, or signing tools present |
| Device | `BLOCKED`: iTunes device count `0`; no Apple USB device; iOS version, pairing, trust, and Developer Mode `NOT TESTED` |
| Artifact status | `BLOCKED`: no `Xinsta.ipa` output path, no final IPA hash, no signature verification, no installation, no runtime result |

### Exact remaining blockers

1. **Rights evidence:** written, non-secret evidence of permission to modify this
   exact third-party IPA for one owner-controlled device. Until supplied,
   building a modified Instagram binary would violate the repository's stated
   rights boundary.
2. **Host software approval:** download and run the official 64-bit Sideloadly
   installer from `https://sideloadly.io/SideloadlySetup64.exe` (v0.71.0),
   verify its Authenticode signature and hash, and accept any UAC prompt. This
   was **not** done because host-software installation needs specific approval.
3. **Signed packaging executor:** the bounded unsigned executor is implemented,
   but an approved signing step must still re-sign the dylib, every nested
   bundle/extension and the app, then write the final signed IPA. The unsigned
   output must not be represented as installable or rights-cleared.
4. **Device/signing inputs:** connect and trust the owner's iPhone, confirm iOS
   and Developer Mode, and supply Apple signing credentials only inside the
   signing tool, never in the repository, logs, or chat.
5. **Post-build verification:** analyzer, signature/provisioning checks, final
   hash, install, launch, and load-marker evidence can only be reported after
   an actual artifact exists.

### Next executable action

Obtain the rights evidence and the specific Sideloadly-install approval. The
unsigned executor may be used only for private review of an authorized source;
do not create a placeholder signed IPA, do not treat the unsigned output as
installable, and do not modify the original `F:\Instagram.ipa`.

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

## Final verification closure — 21 November 2026

This closure records the exact code head and evidence used for the final
readiness decision. It is documentation only; it does not authorize execution.

| Item | Evidence |
| --- | --- |
| Branch | `feature/ig456-private-pilot-identity` |
| Verified code HEAD | `3c38ca96116acf4e689a9519e554ab4b8ff899a0` |
| Repository state | `VERIFIED`: clean tree; `0/0` ahead/behind upstream; `git diff --check` clean; no merge into `main` |
| Changes since `a4f09d7` | `1108a38` pinned display name `Xinsta` and rpath evidence; `3c38ca9` pinned the reviewed dylib hash, rejected all Core load-command kinds, and rejected duplicate rpaths |
| Licensing/API CI | `VERIFIED`: run `44912738704` success at code HEAD: API `58 passed`; Neon guard `2 passed`; analyzer `96 passed`; Build Manager `194 passed`; contract `18 passed`; planner `10 passed`; licensing `Ran 7 tests`; migrations and OpenAPI checks passed |
| Xinsta Core CI | `VERIFIED`: run `44912738700` success at code HEAD: Foundation `114 passed, 0 failed`; simulator `Executed 8 tests, with 0 failures`; unsigned arm64 iOS 16.3 dylib structural validation passed |
| Dylib artifact | `VERIFIED`: artifact `14710343439`, `libXinstaCore-unsigned-arm64-ios16.3`; downloaded bytes SHA-256 `bf58dd04ca747d2d489c92509c9b8e96e2946197ee868c3245fbf5a50a0accff`; one arm64 `MH_DYLIB`, min OS 16.3, SDK 18.5, 21 load commands, no signature, install name `@rpath/libXinstaCore.dylib`, system-only dependencies |
| Source IPA | `VERIFIED`: `F:\Instagram.ipa` SHA-256 `665a814e13d8c187dce5a78d0e8348f73f9081205b927291d7d5d2bce96eb131`; analyzer confirms `com.burbn.instagram`, `456.0.0` (`1114925422`), min iOS 16.3, arm64, `cryptid=0`, 8 URL schemes, 8 extensions |
| Dry-run planner | `VERIFIED` against the exact source and downloaded dylib: `mode=dry_run`, `execution_permitted=false`, `status=READY_FOR_PRIVATE_HOST_REVIEW`, rpath step `already_present`, no Core load command, pilot bundle `com.projectx.xinsta.pilot`, display name `Xinsta`, pilot adapter `com.projectx.xinsta.pilot@456.0.0@1114925422`; all four signing/repackage/install steps blocked |
| Neon STAGING live API | `BLOCKED`: `NEON_STAGING_DATABASE_URL` absent; guarded scripts exit 1 without DB access; no direct authenticated connection string was supplied or taken from unrelated local configuration. Skipped PostgreSQL tests are not a live pass |
| Neon read-only check | `VERIFIED`: authorized read-only connector sees project `late-wind-49091088`, staging branch `br-billowing-art-bd38um5w`, staging compute `ep-crimson-cherry-bdz9jf81`, revision `c8ad20261120`, 10 public tables, and zero users/licenses/codes/products. Production compute is distinct (`ep-falling-bird-bdgbs39b`); no writes were made |
| Neon leftovers | `VERIFIED`: three `test_*` schemas still exist: `test_419ef9234d58e644`, `test_71052392b993781a`, `test_eabedc40e0a21b1a`. They were not deleted or modified |
| iPhone/signing | `BLOCKED`: Apple Mobile Device Service running; iTunes `12.13.10.3` reports device count `0`; no present Apple/iPhone USB device; iOS, pairing, trust and Developer Mode `NOT TESTED`; no signing or iOS deployment tools found; no certificate or profile available |
| Independent review | `VERIFIED`: fresh read-only review of exact code head `3c38ca9` returned `APPROVE WITH NON-BLOCKING NOTES`; no blocking findings. Notes were that the load-command regression matrix covers only load/weak kinds although the implementation is kind-agnostic, and that the dylib mismatch test monkeypatches the pinned literal rather than asserting the literal itself. No code changed after this review; the following commit is documentation only. |

### GO/NO-GO matrix

| Gate | Status | Reason |
| --- | --- | --- |
| Static compatibility | `VERIFIED` | pinned source, identity policy, dylib structure, dry-run planner and CI evidence |
| Signed pilot artifact | `NO-GO` | no signing identity/key, profile, entitlement set, or signed nested bundles |
| Device availability | `NO-GO` | no readable/paired iPhone; iOS and Developer Mode unknown |
| Runtime load proof | `NO-GO` | no launch and no `[XinstaCore] init=` evidence from the pilot process |
| Coexistence/data isolation | `NO-GO` | untested on device; production app/data integrity unverified |
| Authorization | `NO-GO` | no final owner approval for signing, installation, launch, or device changes |

**Physical-device pilot decision: `NO-GO`.** Static and dry-run work is complete;
no signed installable artifact exists and no device was changed.

### Next three prioritized actions

1. Obtain explicit owner approval and supply signing inputs for
   `com.projectx.xinsta.pilot`, pilot App Groups, and a private registered device.
2. Run the reviewed dry-run planner on the signed output and stop on any blocker
   before any installer is used.
3. Reconnect the iPhone read-only, record iOS/Developer Mode without private
   identifiers, install only the pilot, and capture the single load-marker line.
