#!/usr/bin/env bash
# Builds apple/build/Porta.xcframework, the Rust tunnel (libporta.a) for
# macOS, iOS and the iOS simulator, for the PortaKit Swift package in apple/.
# Needs macOS with Xcode and rustup.
#
# Usage: scripts/build-apple.sh [--debug]
set -euo pipefail

[[ $(uname -s) == Darwin ]] || { echo "build-apple.sh needs macOS with Xcode" >&2; exit 2; }
repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
profile=release
cargo_profile=(--release)
if [[ ${1:-} == --debug ]]; then
  profile=debug
  cargo_profile=()
fi
# The oldest systems PortaKit supports (apple/Package.swift); Rust and the
# C code it links must agree on them.
export MACOSX_DEPLOYMENT_TARGET=13.0 IPHONEOS_DEPLOYMENT_TARGET=16.0
targets=(aarch64-apple-darwin x86_64-apple-darwin aarch64-apple-ios aarch64-apple-ios-sim)
rustup target add "${targets[@]}" >/dev/null
for target in "${targets[@]}"; do
  cargo build --manifest-path "$repository_root/rust/Cargo.toml" --package porta-apple \
    --target "$target" "${cargo_profile[@]}" --locked
done

library() { printf '%s/rust/target/%s/%s/libporta.a' "$repository_root" "$1" "$profile"; }
build=$repository_root/apple/build
rm -rf "$build"
mkdir -p "$build/macos" "$build/include"
lipo -create "$(library aarch64-apple-darwin)" "$(library x86_64-apple-darwin)" \
  -output "$build/macos/libporta.a"
cp "$repository_root/rust/porta-apple/include/porta.h" "$build/include/"
cat >"$build/include/module.modulemap" <<'MAP'
module CPorta {
  header "porta.h"
  export *
}
MAP
xcodebuild -create-xcframework \
  -library "$build/macos/libporta.a" -headers "$build/include" \
  -library "$(library aarch64-apple-ios)" -headers "$build/include" \
  -library "$(library aarch64-apple-ios-sim)" -headers "$build/include" \
  -output "$build/Porta.xcframework"
echo "built $build/Porta.xcframework"
