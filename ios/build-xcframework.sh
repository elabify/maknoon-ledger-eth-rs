#!/usr/bin/env bash
# Build LedgerEthCore.xcframework. Framework-bundle slices for
# multi-xcframework coexistence (see ledger-sol-rs / ledger-tron-rs).

set -euo pipefail

CRATE=ledger-eth-core
LIB=libledger_eth_core
FRAMEWORK=LedgerEthCore
PROFILE=release
PROFILE_DIR=release

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if command -v rustup >/dev/null 2>&1; then
    CARGO="$(rustup which cargo)"
    export RUSTC="$(rustup which rustc)"
else
    CARGO="cargo"
fi
echo "[ios] using cargo: $CARGO"
echo "[ios] using rustc: ${RUSTC:-cargo-default}"

echo "[ios] building arm64 device"
"$CARGO" build --release -p "$CRATE" --target aarch64-apple-ios

echo "[ios] building arm64 sim"
"$CARGO" build --release -p "$CRATE" --target aarch64-apple-ios-sim

echo "[ios] building x86_64 sim"
"$CARGO" build --release -p "$CRATE" --target x86_64-apple-ios

echo "[ios] creating universal simulator slice"
mkdir -p "target/universal-sim/$PROFILE_DIR"
lipo -create \
    "target/aarch64-apple-ios-sim/$PROFILE_DIR/$LIB.a" \
    "target/x86_64-apple-ios/$PROFILE_DIR/$LIB.a" \
    -output "target/universal-sim/$PROFILE_DIR/$LIB.a"

echo "[ios] generating Swift bindings"
rm -rf ios/bindings
mkdir -p ios/bindings
"$CARGO" run --release -p "$CRATE" --bin uniffi-bindgen -- \
    generate \
    --library "target/aarch64-apple-ios/$PROFILE_DIR/$LIB.a" \
    --language swift \
    --out-dir ios/bindings

SWIFT_BINDINGS="ios/bindings/ledger_eth_core.swift"
sed -i.bak \
    -e 's/^    static let vtable:/    nonisolated(unsafe) static let vtable:/' \
    -e 's/^    static let vtablePtr:/    nonisolated(unsafe) static let vtablePtr:/' \
    "$SWIFT_BINDINGS"
rm -f "${SWIFT_BINDINGS}.bak"

sed -i.bak \
    -e "s/canImport(ledger_eth_coreFFI)/canImport($FRAMEWORK)/" \
    -e "s/import ledger_eth_coreFFI/import $FRAMEWORK/" \
    "$SWIFT_BINDINGS"
rm -f "${SWIFT_BINDINGS}.bak"

make_framework_slice() {
    local STATIC_LIB="$1"
    local OUT_DIR="$2"
    local PLATFORM="$3"
    local FW_DIR="$OUT_DIR/$FRAMEWORK.framework"

    rm -rf "$FW_DIR"
    mkdir -p "$FW_DIR/Headers" "$FW_DIR/Modules"

    cp "$STATIC_LIB" "$FW_DIR/$FRAMEWORK"
    cp ios/bindings/*.h "$FW_DIR/Headers/"
    cat > "$FW_DIR/Modules/module.modulemap" <<MODMAP
framework module $FRAMEWORK {
    umbrella header "ledger_eth_coreFFI.h"
    export *
    module * { export * }
}
MODMAP

    cat > "$FW_DIR/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDevelopmentRegion</key><string>en</string>
    <key>CFBundleExecutable</key><string>$FRAMEWORK</string>
    <key>CFBundleIdentifier</key><string>com.elabify.$FRAMEWORK</string>
    <key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
    <key>CFBundleName</key><string>$FRAMEWORK</string>
    <key>CFBundlePackageType</key><string>FMWK</string>
    <key>CFBundleShortVersionString</key><string>1.0</string>
    <key>CFBundleSignature</key><string>????</string>
    <key>CFBundleSupportedPlatforms</key>
    <array><string>$PLATFORM</string></array>
    <key>CFBundleVersion</key><string>1</string>
</dict>
</plist>
PLIST
}

echo "[ios] wrapping device slice as framework"
mkdir -p target/framework-device
make_framework_slice \
    "target/aarch64-apple-ios/$PROFILE_DIR/$LIB.a" \
    target/framework-device \
    iPhoneOS

echo "[ios] wrapping universal sim slice as framework"
mkdir -p target/framework-sim
make_framework_slice \
    "target/universal-sim/$PROFILE_DIR/$LIB.a" \
    target/framework-sim \
    iPhoneSimulator

echo "[ios] assembling xcframework"
rm -rf "ios/$FRAMEWORK.xcframework"
xcodebuild -create-xcframework \
    -framework "target/framework-device/$FRAMEWORK.framework" \
    -framework "target/framework-sim/$FRAMEWORK.framework" \
    -output "ios/$FRAMEWORK.xcframework"

echo "[ios] done: ios/$FRAMEWORK.xcframework"
echo "[ios] Swift glue: ios/bindings/*.swift"
