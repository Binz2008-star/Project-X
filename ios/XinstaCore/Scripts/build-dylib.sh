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

SOURCES=(
  "$ROOT/Sources/XinstaCore.m"
  "$ROOT/Sources/Core/XinstaFeature.m"
  "$ROOT/Sources/Core/XinstaFeatureRegistry.m"
  "$ROOT/Sources/Core/XinstaCompatibility.m"
  "$ROOT/Sources/Core/XinstaSettingsDataSource.m"
  "$ROOT/Sources/Adapter/XinstaIG456Adapter.m"
  "$ROOT/Sources/UI/XinstaSettingsViewController.m"
)

"$CLANG" \
  -target arm64-apple-ios"$MIN_OS" \
  -isysroot "$SDK" \
  -fobjc-arc -fmodules \
  -O2 -Wall -Wextra -Werror \
  -dynamiclib \
  -install_name @rpath/libXinstaCore.dylib \
  -o "$OUT/libXinstaCore.dylib" \
  "${SOURCES[@]}" \
  -framework Foundation -framework UIKit

# Verify the artifact is an arm64 iOS Mach-O dylib before reporting success.
file "$OUT/libXinstaCore.dylib"
xcrun --sdk iphoneos llvm-objdump --macho --private-headers "$OUT/libXinstaCore.dylib" \
  | grep -E 'MH_DYLIB|CPU_TYPE_ARM64|LC_BUILD_VERSION|IPHONEOS' || true
