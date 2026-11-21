#!/usr/bin/env bash
# Compile the unsigned Xinsta Core dylib with the iOS SDK.
# Intended for GitHub macOS runners; requires Xcode with an iOS SDK.
# No signing identity, provisioning profile, or Apple credentials are used.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:-$ROOT/build}"
mkdir -p "$OUT"

SDK="$(xcrun --sdk iphoneos --show-sdk-path)"
CLANG="$(xcrun --sdk iphoneos -f clang)"
MIN_OS="16.3"
INSTALL_NAME="@rpath/libXinstaCore.dylib"

SOURCES=(
  "$ROOT/Sources/XinstaCore.m"
  "$ROOT/Sources/Core/XinstaFeature.m"
  "$ROOT/Sources/Core/XinstaFeatureRegistry.m"
  "$ROOT/Sources/Core/XinstaCompatibility.m"
  "$ROOT/Sources/Core/XinstaIdentityPolicy.m"
  "$ROOT/Sources/Core/XinstaHostMetadata.m"
  "$ROOT/Sources/Core/XinstaSettingsDataSource.m"
  "$ROOT/Sources/Adapter/XinstaIG456Adapter.m"
  "$ROOT/Sources/Adapter/XinstaDiagnostic.m"
  "$ROOT/Sources/UI/XinstaSettingsViewController.m"
  "$ROOT/Sources/UI/XinstaSettingsPresenter.m"
)

"$CLANG" \
  -target arm64-apple-ios"$MIN_OS" \
  -isysroot "$SDK" \
  -fobjc-arc -fmodules \
  -I "$ROOT/Sources" -I "$ROOT/Sources/Core" -I "$ROOT/Sources/Adapter" -I "$ROOT/Sources/UI" \
  -O2 -Wall -Wextra -Werror \
  -dynamiclib \
  -install_name "$INSTALL_NAME" \
  -o "$OUT/libXinstaCore.dylib" \
  "${SOURCES[@]}" \
  -framework Foundation -framework UIKit

# Verify the artifact is an unsigned arm64 iOS Mach-O dylib targeting 16.3.
# Every check fails explicitly; no validation result is suppressed.
ARTIFACT="$OUT/libXinstaCore.dylib"

if [[ ! -f "$ARTIFACT" ]]; then
  echo "ERROR: expected artifact not found: $ARTIFACT" >&2
  exit 1
fi
if [[ ! -s "$ARTIFACT" ]]; then
  echo "ERROR: artifact is empty: $ARTIFACT" >&2
  exit 1
fi

FILE_DESCRIPTION="$(file -b "$ARTIFACT")"
echo "file: $FILE_DESCRIPTION"
if ! grep -q 'Mach-O 64-bit' <<<"$FILE_DESCRIPTION"; then
  echo "ERROR: artifact is not a 64-bit Mach-O file" >&2
  exit 1
fi
if ! grep -q 'arm64' <<<"$FILE_DESCRIPTION"; then
  echo "ERROR: artifact is not arm64" >&2
  exit 1
fi
if ! grep -qi 'dynamically linked shared library' <<<"$FILE_DESCRIPTION"; then
  echo "ERROR: artifact is not a dynamic library (dylib)" >&2
  exit 1
fi

MACHO_HEADER="$(otool -hv "$ARTIFACT")"
echo "$MACHO_HEADER"
if ! grep -q 'MH_MAGIC_64' <<<"$MACHO_HEADER"; then
  echo "ERROR: artifact lacks a 64-bit Mach-O header" >&2
  exit 1
fi
if ! grep -q 'ARM64' <<<"$MACHO_HEADER"; then
  echo "ERROR: Mach-O header does not declare ARM64" >&2
  exit 1
fi
if ! grep -q 'DYLIB' <<<"$MACHO_HEADER"; then
  echo "ERROR: Mach-O filetype is not MH_DYLIB" >&2
  exit 1
fi

LOAD_COMMANDS="$(otool -l "$ARTIFACT")"
if grep -q 'LC_BUILD_VERSION' <<<"$LOAD_COMMANDS"; then
  BUILD_VERSION_BLOCK="$(grep -A 6 'LC_BUILD_VERSION' <<<"$LOAD_COMMANDS")"
  echo "--- LC_BUILD_VERSION ---"
  echo "$BUILD_VERSION_BLOCK"
  echo "-------------------------"
  if ! grep -qE 'platform[[:space:]]+(IPHONEOS|2)([[:space:]]|$)' <<<"$BUILD_VERSION_BLOCK"; then
    echo "ERROR: LC_BUILD_VERSION platform is not iOS" >&2
    exit 1
  fi
  if ! grep -qE 'minos[[:space:]]+16\.3([[:space:]]|$)' <<<"$BUILD_VERSION_BLOCK"; then
    echo "ERROR: minimum OS is not 16.3" >&2
    exit 1
  fi
elif grep -q 'LC_VERSION_MIN_IPHONEOS' <<<"$LOAD_COMMANDS"; then
  if ! grep -qE 'version[[:space:]]+16\.3([[:space:]]|$)' <<<"$LOAD_COMMANDS"; then
    echo "ERROR: minimum OS is not 16.3" >&2
    exit 1
  fi
else
  echo "ERROR: artifact does not target iOS" >&2
  exit 1
fi

if grep -q 'LC_CODE_SIGNATURE' <<<"$LOAD_COMMANDS"; then
  echo "ERROR: artifact must be unsigned but contains LC_CODE_SIGNATURE" >&2
  exit 1
fi

INSTALL_NAMES="$(otool -L "$ARTIFACT")"
echo "--- LC_ID_DYLIB / dependencies ---"
echo "$INSTALL_NAMES"
echo "----------------------------------"
if ! grep -qF "$INSTALL_NAME" <<<"$INSTALL_NAMES"; then
  echo "ERROR: expected install name $INSTALL_NAME is missing" >&2
  exit 1
fi

echo "Xinsta Core artifact validation passed: unsigned arm64 iOS 16.3 dylib"
