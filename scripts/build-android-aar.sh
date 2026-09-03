#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ANDROID_HOME="${ANDROID_HOME:-/home/azadmin/Android/Sdk}"
ANDROID_NDK_HOME="${ANDROID_NDK_HOME:-${ANDROID_HOME}/ndk/27.2.12479018}"
GOMOBILE="${GOMOBILE:-$(command -v gomobile || true)}"
OUTPUT="${1:-${ROOT}/android/app/build/generated/aar/portamobile.aar}"

if [[ -z "${GOMOBILE}" ]]; then
    GOPATH_BIN="$(go env GOPATH 2>/dev/null)/bin"
    if [[ -x "${GOPATH_BIN}/gomobile" ]]; then
        GOMOBILE="${GOPATH_BIN}/gomobile"
    else
        echo "gomobile is required; install golang.org/x/mobile/cmd/gomobile" >&2
        exit 1
    fi
fi
if [[ ! -d "${ANDROID_NDK_HOME}" ]]; then
    echo "Android NDK 27.2.12479018 not found at ${ANDROID_NDK_HOME}" >&2
    exit 1
fi

mkdir -p "$(dirname "${OUTPUT}")"
cd "${ROOT}"
PATH="$(dirname "${GOMOBILE}"):${PATH}" \
    ANDROID_HOME="${ANDROID_HOME}" ANDROID_NDK_HOME="${ANDROID_NDK_HOME}" \
    "${GOMOBILE}" bind \
    -target=android/arm,android/arm64,android/amd64 \
    -androidapi=26 -trimpath -ldflags="-s -w" \
    -o "${OUTPUT}" ./mobile/portamobile
