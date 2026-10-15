#!/usr/bin/env bash
# 无 make 时的一键编译脚本（Linux Theos 工具链 / macOS Xcode 均可）
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

if [[ -z "${SDK:-}" ]]; then
  if command -v xcrun >/dev/null 2>&1; then
    SDK="$(xcrun --sdk iphoneos --show-sdk-path)"
    CC="${CC:-$(xcrun --sdk iphoneos -f clang)}"
  elif [[ -n "${THEOS:-}" && -d "$THEOS/sdks" ]]; then
    SDK="$(ls -d "$THEOS"/sdks/iPhoneOS*.sdk 2>/dev/null | sort | tail -1)"
    CC="${CC:-$THEOS/toolchain/linux/iphone/bin/clang}"
  else
    echo "请设置 SDK=... 与 CC=...（见 README）" >&2
    exit 1
  fi
fi
CC="${CC:-clang}"
MIN_IOS="${MIN_IOS:-14.0}"
TARGET="arm64-apple-ios${MIN_IOS}"

mkdir -p build
CFLAGS=(-target "$TARGET" -fobjc-arc -fPIC -O2 -Wall -isysroot "$SDK" -Ivendor/fishhook)
LDFLAGS=(-target "$TARGET" -isysroot "$SDK" -dynamiclib -framework Foundation
         -install_name @rpath/TelegramAntiRecall.dylib)

"$CC" "${CFLAGS[@]}" -c src/AntiRecall.m -o build/AntiRecall.o
"$CC" "${CFLAGS[@]}" -c vendor/fishhook/fishhook.c -o build/fishhook.o
"$CC" "${LDFLAGS[@]}" -o build/TelegramAntiRecall.dylib build/AntiRecall.o build/fishhook.o
echo "OK -> build/TelegramAntiRecall.dylib"
ls -la build/TelegramAntiRecall.dylib
