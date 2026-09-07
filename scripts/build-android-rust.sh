#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
output_dir="${1:-$repo_root/android/app/build/generated/jniLibs}"
cargo="${CARGO:-$HOME/.cargo/bin/cargo}"
rustup="${RUSTUP:-$HOME/.cargo/bin/rustup}"
cargo_target_dir="${CARGO_TARGET_DIR:-$repo_root/rust/target}"
android_home="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-$HOME/Android/Sdk}}"
ndk_root="${ANDROID_NDK_ROOT:-${ANDROID_NDK_HOME:-$android_home/ndk/27.2.12479018}}"

if [[ ! -x "$cargo" ]]; then
    cargo="$(command -v cargo)"
fi
if [[ ! -x "$rustup" ]]; then
    rustup="$(command -v rustup)"
fi
if [[ ! -d "$ndk_root" ]]; then
    printf 'Android NDK not found at %s\n' "$ndk_root" >&2
    exit 1
fi

host_tag="linux-x86_64"
case "$(uname -s)-$(uname -m)" in
    Darwin-arm64|Darwin-x86_64) host_tag="darwin-x86_64" ;;
esac
toolchain="$ndk_root/toolchains/llvm/prebuilt/$host_tag"
if [[ ! -d "$toolchain" ]]; then
    printf 'Android NDK toolchain not found at %s\n' "$toolchain" >&2
    exit 1
fi

targets=(
    "aarch64-linux-android:arm64-v8a:aarch64-linux-android26-clang"
    "armv7-linux-androideabi:armeabi-v7a:armv7a-linux-androideabi26-clang"
    "x86_64-linux-android:x86_64:x86_64-linux-android26-clang"
)

installed="$("$rustup" target list --installed)"
for item in "${targets[@]}"; do
    IFS=: read -r target _abi _linker <<<"$item"
    if ! grep -qx "$target" <<<"$installed"; then
        "$rustup" target add "$target"
    fi
done

mkdir -p "$output_dir"
for item in "${targets[@]}"; do
    IFS=: read -r target abi linker <<<"$item"
    linker_path="$toolchain/bin/$linker"
    if [[ ! -x "$linker_path" ]]; then
        printf 'Android linker not found at %s\n' "$linker_path" >&2
        exit 1
    fi
    linker_var="CARGO_TARGET_$(tr '[:lower:]-' '[:upper:]_' <<<"$target")_LINKER"
    target_var="$(tr '-' '_' <<<"$target")"
    env "$linker_var=$linker_path" \
        "CARGO_TARGET_DIR=$cargo_target_dir" \
        "CC_$target_var=$linker_path" \
        "CXX_$target_var=$toolchain/bin/${linker}++" \
        "AR_$target_var=$toolchain/bin/llvm-ar" \
        "RANLIB_$target_var=$toolchain/bin/llvm-ranlib" \
        "$cargo" build \
        --manifest-path "$repo_root/rust/Cargo.toml" \
        --package porta-android \
        --target "$target" \
        --release \
        --locked
    mkdir -p "$output_dir/$abi"
    cp "$cargo_target_dir/$target/release/libporta_android.so" \
        "$output_dir/$abi/libporta_android.so"
done
