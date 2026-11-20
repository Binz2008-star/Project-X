#!/usr/bin/env bash
# Compile and run the Foundation-only Xinsta Core tests on macOS.
# UIKit sources are intentionally excluded; those compile in build-dylib.sh.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:-$ROOT/build}"
mkdir -p "$OUT"

SDK="$(xcrun --sdk macosx --show-sdk-path)"
CLANG="$(xcrun --sdk macosx -f clang)"

"$CLANG" \
  -isysroot "$SDK" \
  -fobjc-arc -fmodules \
  -O1 -Wall -Wextra -Werror \
  -I "$ROOT/Sources/Core" -I "$ROOT/Sources/Adapter" \
  -o "$OUT/xinsta-core-tests" \
  "$ROOT/Tests/XinstaCoreTests.m" \
  "$ROOT/Sources/Core/XinstaFeature.m" \
  "$ROOT/Sources/Core/XinstaFeatureRegistry.m" \
  "$ROOT/Sources/Core/XinstaCompatibility.m" \
  "$ROOT/Sources/Core/XinstaSettingsDataSource.m" \
  "$ROOT/Sources/Adapter/XinstaIG456Adapter.m" \
  -framework Foundation

"$OUT/xinsta-core-tests"
