# Instagram 456.0.0 / DLInsta static evidence

Status: **STATIC ANALYSIS ONLY**. No IPA was executed, extracted to the repository,
injected, signed, repackaged, installed, or launched. No runtime hook, preference
write, X Settings presentation, or device behaviour is claimed here.

## Classification rules

| Status | Meaning |
| --- | --- |
| `VERIFIED` | Directly observed in the immutable artifact bytes or static metadata. Static presence is not runtime behaviour. |
| `FAILED` | Checked and contradicted by the artifact bytes. |
| `BLOCKED` | Checked as far as the available static tooling permits; remaining resolution requires approved tooling or runtime access. |
| `NOT TESTED` | Requires an authorized runtime or device environment that has not been provided. |

## Artifacts

| Artifact | Metadata / SHA-256 | Result |
| --- | --- | --- |
| `Instagram (v452.0.0) + DLInsta (v3.0.0).ipa` | filename says 452, `Info.plist` reports **452.0.1** / build **1093431980**; archive SHA-256 `8e44bcf73531d66dc1382b6f994f2827f1d9115000ca531ed9b849d919660998` | `VERIFIED` |
| 452 main executable | SHA-256 `a57fa3bd0ffe21e04f91983aa2605c96b6dbdbbac6caba9cac434892707103a2`; `cryptid=0`; arm64 | `VERIFIED` |
| DLInsta 3.0.0 dylib | SHA-256 `21ad0195c13691fe1230d519c022c75013e62abc2954f01e83f8706aabc8893a`; 187 Objective-C classes; 3 category entries | `VERIFIED` |
| `Instagram (v453.0.0) + DLInsta (v3.0.2).ipa` | `Info.plist` reports **453.0.0** / build **1099096960**; archive SHA-256 `d07a5f3dda4ada2997a11f0a79e00c97e4110793c5f61f66de96eb2705c1904` | `VERIFIED` |
| 453 main executable | SHA-256 `55ff123fffbc099788d9090b6f6e7e3689e6f2a08b485f2c349fa2cce7ee2d22`; `cryptid=0`; arm64 | `VERIFIED` |
| DLInsta 3.0.2 dylib | SHA-256 `159adedb335a1d78b36a5dce42768012580a590a3d09e8c47ec964e43fb656d0`; 187 Objective-C classes; 3 category entries | `VERIFIED` |
| owner-provided target IPA | `com.burbn.instagram`, **456.0.0**, build **1114925422**, minimum iOS 16.3; archive SHA-256 `665a814e13d8c187dce5a78d0e8348f73f9081205B927291D7D5D2BCE96EB131` | `VERIFIED` |
| target main executable | SHA-256 `4fb7ae5c16c91e77104bdc173c173df9d09a8e0a92ce356d558ffefcf9253378`; `cryptid=0`; arm64 | `VERIFIED` |

The 452 filename is imprecise: evidence reports the value inside `Info.plist`,
not the filename.

## Evidence levels

### 1. Selector string present

| Observation | 452 | 453 | 456 target | Status |
| --- | --- | --- | --- | --- |
| `IGProfileSheetTableViewController` in Objective-C class metadata | present | present | present | `VERIFIED` |
| `tableView:numberOfRowsInSection:` in `__objc_methname` | present | present | present | `VERIFIED` |
| `tableView:cellForRowAtIndexPath:` in `__objc_methname` | present | present | present | `VERIFIED` |
| `tableView:didSelectRowAtIndexPath:` in `__objc_methname` | present | present | present | `VERIFIED` |
| same three table-view selectors in `__objc_selrefs` | present | present | present | `VERIFIED` |
| any of the above in the DLInsta dylib | absent | absent | not applicable | `FAILED` |

These are static-presence facts. They do not prove that the target class
implements those selectors, that DLInsta hooks them, or that a hook is safe.

### 2. Class and method reference confirmed

- The target class name was recovered from `__objc_classlist` → `class_ro` →
  class-name metadata in all three main executables after accounting for modern
  arm64 chained-fixup pointer tagging. `VERIFIED`.
- The three table-view selectors are present as strings and selector references
  in all three main executables. `VERIFIED`.
- Ownership of each selector by `IGProfileSheetTableViewController` could not be
  resolved because the relevant method lists use relative offsets that the
  read-only Python inspector does not fully decode. This is a tooling limit, not
  evidence of absence: `BLOCKED`.
- DLInsta category names `SafeGetters`, `DLTTrim`, and `DLTMore` are present in
  both reference dylibs, but their chained-fixup target-class pointers were not
  resolved. No DLInsta-to-IG456 category binding is claimed: `BLOCKED`.

### 3. Interception implementation identified

Both reference DLInsta dylibs import the same runtime primitives:

```
_NSClassFromString
_NSSelectorFromString
_objc_getClass
_class_getInstanceMethod
_method_getImplementation
_method_setImplementation
_class_addMethod
_dlopen
_dlsym
```

This is `VERIFIED` static evidence that the library contains capability for
runtime lookup and method implementation replacement. It is **not** proof that
those primitives are called against Instagram 456 or against
`IGProfileSheetTableViewController`.

Additional static strings common to both versions include
`@"IGDirectThreadViewController"`, `dl_showOptionsCopy:`,
`dl_onLikeButtonPressedWithOriginalBlock:`, `dltActionType`, and
`setDltActionType:`. They identify candidate integration areas in the reference
tweaks, not verified hooks in the target. `VERIFIED` as strings; runtime binding
is `BLOCKED`.

`method_exchangeImplementations` and `class_replaceMethod` were not observed in
the DLInsta import set. `FAILED` for those specific import names; this does not
rule out other interception mechanisms.

### 4. Preference-to-implementation linkage identified

Both DLInsta versions import:

```
_CFPreferencesCopyAppValue
_CFPreferencesSetAppValue
_CFPreferencesAppSynchronize
_kCFPreferencesCurrentApplication
_OBJC_CLASS_$_NSUserDefaults
```

Static `VERIFIED`: preference APIs are present. No preference domain/key was
mapped to a specific hook, feature, or UI action from the available strings;
the linkage from a preference value to an implementation is therefore `BLOCKED`.

### 5. Runtime verification

| Question | Status | Reason |
| --- | --- | --- |
| Does the 456 executable load `DLInsta.dylib`? | `FAILED` | No DLInsta load command exists in the target executable. The 452/453 reference executables do contain a weak-load dependency; the target does not. |
| Does DLInsta load successfully inside Instagram 456? | `NOT TESTED` | Requires an authorized, signed, injected app copy. |
| Does `IGProfileSheetTableViewController` exist at runtime in 456? | `NOT TESTED` | Static class metadata is present; runtime gets must be observed in the authorized host. |
| Are the three selectors implemented by that runtime class? | `NOT TESTED` | Requires `objc_getClass` / `class_getInstanceMethod` evidence in the running host. |
| Is any method implementation actually replaced? | `NOT TESTED` | Requires explicit owner-authorized hook proof. |
| Does X Settings present from Instagram UI? | `NOT TESTED` | No host presentation hook exists and no device test is authorized. |
| Does a preference toggle change a verified hook outcome? | `NOT TESTED` | Requires both a verified hook and an authorized runtime. |

## Instagram 456 compatibility matrix

| Integration point | Static observation | Status |
| --- | --- | --- |
| Exact bundle identifier `com.burbn.instagram` | `Info.plist` | `VERIFIED` |
| Exact version `456.0.0` | `Info.plist` | `VERIFIED` |
| Exact build `1114925422` | `Info.plist` | `VERIFIED` |
| Minimum OS 16.3 | `Info.plist` | `VERIFIED` |
| Unencrypted arm64 executable | `cryptid=0`, arm64 slice | `VERIFIED` |
| Target class name | recovered from Objective-C class metadata | `VERIFIED` |
| Required table-view selector strings | present in `__objc_methname` | `VERIFIED` |
| Required table-view selector references | present in `__objc_selrefs` | `VERIFIED` |
| Selector ownership and type encodings on the target class | relative method-list fixups unresolved | `BLOCKED` |
| DLInsta dependency in 452/453 reference hosts | weak-load command present | `VERIFIED` |
| DLInsta dependency in 456 target | load command absent | `FAILED` |
| DLInsta hook primitive availability | imports listed above | `VERIFIED` |
| DLInsta hook bound to the 456 target class | no target-class string in DLInsta; static fixup binding unresolved | `BLOCKED` |
| Preference key → implementation linkage | APIs present, key mapping not resolved | `BLOCKED` |
| Safe X Settings presentation from host | no host hook implemented | `NOT TESTED` |
| Runtime launch, hook, UI, persistence, crash behaviour | no authorized runtime | `NOT TESTED` |

## Consequence for Xinsta

The static evidence supports a strict metadata-and-symbol gate, but it does not
justify a hook, an injection plan, or a claim of Instagram integration. The
Phase 3 code therefore keeps compatibility read-only, binds every feature to an
explicit adapter identifier, blocks presentation when the target or adapter is
unavailable, and emits only fixed diagnostic codes.

Runtime proof remains `NOT TESTED`; it is blocked pending explicit written
owner authorization, an authorized app copy, signing identity, provisioning
profile, registered UDID, approved injection method, and a verified hook path.
