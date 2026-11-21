# Instagram 456 load-only proof runbook

Status: **AUTHORIZED FOR A NARROW LOAD-ONLY TEST; NOT TESTED IN THIS REPOSITORY**.

The owner scoped a private runtime test to prove only that the unsigned
`libXinstaCore.dylib` loads inside an owner-controlled copy of Instagram
`456.0.0`, build `1114925422`. The approved environment is a local macOS host
with the registered iPhone 13 attached, signing material injected through the
keychain or environment, and a dylib load-command insert into a copy of the
exact inspected IPA.

This runbook is not a hook plan. It does not authorize X Settings presentation,
swizzling, feature use, account login, redistribution, commercial use, a merge,
or any change to `main`. The repository tool remains dry-run-only:
`execution_permitted` stays `false` and all signing/device steps stay blocked.

## Pinned inputs

| Field | Required value |
| --- | --- |
| Bundle identifier | `com.burbn.instagram` |
| Version | `456.0.0` |
| Build | `1114925422` |
| Original IPA SHA-256 | `665a814e13d8c187dce5a78d0e8348f73f9081205b927291d7d5d2bce96eb131` |
| Core install name | `@rpath/libXinstaCore.dylib` |
| Constructor marker | `[XinstaCore] init=` |
| Adapter identifier | `com.burbn.instagram@456.0.0@1114925422` |

Never place an IPA, certificate, provisioning profile, UDID, Apple ID, device
log, or private path in a commit, issue, pull request, or chat message. Use a
private evidence directory outside the repository and redact identifiers before
sharing any summary.

## Required host inputs

Supply these on the macOS host without writing secret values into scripts or
the repository:

- `IPA_PATH`: the exact owner-provided IPA copy.
- `XINSTA_DYLIB_PATH`: unsigned dylib produced from the reviewed source head.
- `INSERT_DYLIB`: path to a locally reviewed load-command insertion binary.
- `IOS_SIGNING_IDENTITY`: keychain identity name only, never the key material.
- `IOS_PROVISIONING_PROFILE`: path to a development profile matching the app
  identifier and the registered iPhone 13.
- `IOS_DEVICE_UDID`: injected as a secret; never echoed into shared evidence.
- `WORK_DIR` and `EVIDENCE_DIR`: private, mode `0700` directories.
- `REPO`: local checkout of this branch at the exact reviewed head.

All commands below are run on that macOS host, not by the repository code.

## 1. Record the reviewed source head

```bash
set -euo pipefail
umask 077
test -n "${WORK_DIR:-}" && test -n "${EVIDENCE_DIR:-}"
case "$WORK_DIR" in
  /*) ;;
  *) echo "WORK_DIR must be absolute" >&2; exit 1 ;;
esac
case "$WORK_DIR" in
  "$HOME"|"$HOME"/*) ;;
  *) echo "WORK_DIR must be under the operator home directory" >&2; exit 1 ;;
esac
test "$WORK_DIR" != "$HOME"
mkdir -p "$WORK_DIR" "$EVIDENCE_DIR"
chmod 700 "$WORK_DIR" "$EVIDENCE_DIR"
git -C "$REPO" status --short > "$EVIDENCE_DIR/source-status.txt"
git -C "$REPO" rev-parse HEAD > "$EVIDENCE_DIR/source-head.txt"
git -C "$REPO" rev-parse --abbrev-ref HEAD > "$EVIDENCE_DIR/source-branch.txt"
```

Stop if the working tree is dirty or the head is not the independently reviewed
head for this branch.

## 2. Verify the original artifact without modifying it

```bash
ORIGINAL_SHA="$(shasum -a 256 "$IPA_PATH" | awk '{print $1}')"
test "$ORIGINAL_SHA" = "665a814e13d8c187dce5a78d0e8348f73f9081205b927291d7d5d2bce96eb131"

unzip -p "$IPA_PATH" 'Payload/*.app/Info.plist' > "$WORK_DIR/Info.plist"
test "$(plutil -extract CFBundleIdentifier raw -o - "$WORK_DIR/Info.plist")" = "com.burbn.instagram"
test "$(plutil -extract CFBundleShortVersionString raw -o - "$WORK_DIR/Info.plist")" = "456.0.0"
test "$(plutil -extract CFBundleVersion raw -o - "$WORK_DIR/Info.plist")" = "1114925422"

printf '%s\n' "$ORIGINAL_SHA" > "$EVIDENCE_DIR/original-sha256.txt"
plutil -extract CFBundleIdentifier raw -o - "$WORK_DIR/Info.plist" > "$EVIDENCE_DIR/bundle-id.txt"
plutil -extract CFBundleShortVersionString raw -o - "$WORK_DIR/Info.plist" > "$EVIDENCE_DIR/version.txt"
plutil -extract CFBundleVersion raw -o - "$WORK_DIR/Info.plist" > "$EVIDENCE_DIR/build.txt"
```

Any mismatch is a hard stop. Do not sign, inject, or install a substituted
artifact.

## 3. Build and validate the unsigned core

```bash
bash "$REPO/ios/XinstaCore/Scripts/build-dylib.sh" "$WORK_DIR/build" \
  | tee "$EVIDENCE_DIR/dylib-build.txt"
bash "$REPO/ios/XinstaCore/Scripts/run-tests.sh" \
  | tee "$EVIDENCE_DIR/dylib-tests.txt"
shasum -a 256 "$WORK_DIR/build/libXinstaCore.dylib" \
  > "$EVIDENCE_DIR/dylib-sha256.txt"
```

Use that generated dylib as the only injection input. The script already
asserts arm64, iOS 16.3, `MH_DYLIB`, unsigned status, and the expected install
name.

## 4. Prepare a disposable app copy

```bash
UNPACK_DIR="$WORK_DIR/unpacked"
rm -rf "$UNPACK_DIR"
mkdir -p "$UNPACK_DIR"
unzip -q "$IPA_PATH" -d "$UNPACK_DIR"

APP_PATH="$(find "$UNPACK_DIR/Payload" -maxdepth 1 -type d -name '*.app' -print -quit)"
test -n "$APP_PATH"
EXECUTABLE_NAME="$(plutil -extract CFBundleExecutable raw -o - "$WORK_DIR/Info.plist")"
EXECUTABLE_PATH="$APP_PATH/$EXECUTABLE_NAME"
test -f "$EXECUTABLE_PATH"
test ! -e "$APP_PATH/Frameworks/libXinstaCore.dylib"

mkdir -p "$APP_PATH/Frameworks"
cp "$WORK_DIR/build/libXinstaCore.dylib" "$APP_PATH/Frameworks/libXinstaCore.dylib"
```

This modifies only the disposable copy under `WORK_DIR`. The original IPA is
read-only.

## 5. Insert the load command and rpath

```bash
"$INSERT_DYLIB" --inplace --all-yes "@rpath/libXinstaCore.dylib" "$EXECUTABLE_PATH"

if ! otool -l "$EXECUTABLE_PATH" \
  | grep -A2 'LC_RPATH' \
  | grep -qF '@executable_path/Frameworks'; then
  install_name_tool -add_rpath '@executable_path/Frameworks' "$EXECUTABLE_PATH"
fi

otool -L "$EXECUTABLE_PATH" | grep -F '@rpath/libXinstaCore.dylib' \
  > "$EVIDENCE_DIR/load-command.txt"
otool -l "$EXECUTABLE_PATH" | grep -A2 'LC_RPATH' \
  | grep -F '@executable_path/Frameworks' \
  > "$EVIDENCE_DIR/rpath.txt"
```

Stop if either verification file is empty. Do not proceed with a binary that
does not reference the exact core install name and staged Frameworks rpath.

## 6. Re-sign the disposable copy

```bash
cp "$IOS_PROVISIONING_PROFILE" "$APP_PATH/embedded.mobileprovision"

codesign --force --sign "$IOS_SIGNING_IDENTITY" --timestamp=none \
  "$APP_PATH/Frameworks/libXinstaCore.dylib"

while IFS= read -r -d '' nested; do
  codesign --force --sign "$IOS_SIGNING_IDENTITY" --timestamp=none "$nested"
done < <(find "$APP_PATH" -type d -name '*.framework' -print0)

codesign --force --sign "$IOS_SIGNING_IDENTITY" --timestamp=none "$APP_PATH"
codesign --verify --strict --verbose=2 "$APP_PATH" \
  > "$EVIDENCE_DIR/local-codesign-verify.txt" 2>&1
```

Stop on any signing error. This is a local structural check, not a claim that
Apple notarization or App Store review approved the copy.

## 7. Repackage and hash the test copy

```bash
REPACKED_IPA="$WORK_DIR/ig456-load-proof.ipa"
rm -f "$REPACKED_IPA"
(cd "$UNPACK_DIR" && zip -qry "$REPACKED_IPA" Payload)
shasum -a 256 "$REPACKED_IPA" > "$EVIDENCE_DIR/repacked-sha256.txt"
```

Keep both original and repacked hashes in the private evidence bundle. They are
different artifacts; only the original hash is the pinned identity evidence.

## 8. Install and launch on the authorized iPhone 13

Confirm the attached device before using its identifier:

```bash
idevice_id -l | grep -Fx "$IOS_DEVICE_UDID" > /dev/null
```

Install the repacked copy using the approved local tool:

```bash
ios-deploy --id "$IOS_DEVICE_UDID" --bundle "$REPACKED_IPA" --no-wifi \
  > "$EVIDENCE_DIR/install.txt" 2>&1
```

Start a private device log capture, then launch the app once using the
approved method. Do not log in to an account and do not exercise any feature.
The only target signal is the constructor marker.

```bash
idevicesyslog -u "$IOS_DEVICE_UDID" > "$EVIDENCE_DIR/device-syslog.raw" 2>&1 &
SYSLOG_PID=$!
ios-deploy --id "$IOS_DEVICE_UDID" --bundle "$REPACKED_IPA" --justlaunch \
  >> "$EVIDENCE_DIR/install.txt" 2>&1 || true
sleep 20
kill "$SYSLOG_PID" 2>/dev/null || true
wait "$SYSLOG_PID" 2>/dev/null || true

grep -F '[XinstaCore] init=' "$EVIDENCE_DIR/device-syslog.raw" \
  > "$EVIDENCE_DIR/xinsta-core-load-marker.txt"
```

The app process name must be present on the matching console line. A marker
from another process is not host-load evidence.

## Evidence required before claiming `VERIFIED`

All of the following must exist in the private evidence bundle:

1. exact reviewed source head and clean source status;
2. original IPA hash and Info.plist values matching the pinned table;
3. dylib build/test logs and dylib hash;
4. `load-command.txt` showing `@rpath/libXinstaCore.dylib`;
5. `rpath.txt` showing `@executable_path/Frameworks`;
6. local codesign verification output with no errors;
7. repacked IPA hash;
8. attached-device confirmation for the injected UDID;
9. install/launch command output;
10. a console line containing the target process name and `[XinstaCore] init=`.

Record the exact fixed status emitted by the marker, for example
`init=ready`, `init=adapter_not_accepted`, or another documented code. Do not
rewrite a non-ready status as success. The presence of the marker proves that
the constructor ran; `ready` additionally proves the read-only compatibility
gate accepted the host. Neither result proves a hook, X Settings presentation,
or device feature behavior.

Until those items are collected, the status remains `NOT TESTED`. After review
of the private evidence, write only a redacted summary to the repository. Never
commit the raw syslog, UDID, signing identity, provisioning profile, IPA, or
private paths.
