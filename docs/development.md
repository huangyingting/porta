# Development and releases

## Requirements

Go builds require Go 1.26 or newer. Android builds additionally require JDK 17,
Android SDK 35, Android NDK 27.2.12479018, and matching `gomobile` and `gobind`
binaries on `PATH`.

## Local validation

```sh
make test
make test-race
make vet
make build
make build-windows
make android
```

`make test` enables the official `GODEBUG=http2xconnect=1` switch required by
the HTTP/2 Extended CONNECT integration tests.

Linux binaries are written to `bin/`. The Windows target creates
`bin/porta-client-windows-amd64.zip`. Optimized per-architecture Android APKs
are written under `android/app/build/outputs/apk/release/`.

## Android signing

Local Android release builds use the debug signing key unless all production
signing variables are configured:

```sh
export PORTA_ANDROID_KEYSTORE=/secure/path/porta-release.jks
export PORTA_ANDROID_KEYSTORE_PASSWORD='...'
export PORTA_ANDROID_KEY_ALIAS=porta
export PORTA_ANDROID_KEY_PASSWORD='...'
make android
```

Do not commit a keystore or its passwords. Prefer managed Play App Signing for
public distribution.

## GitHub releases

The CI workflow is currently manual. Tags matching `vMAJOR.MINOR.PATCH` run the
release workflow and publish:

- Linux AMD64 and ARM64 servers, clients, and key generators;
- the Windows desktop and CLI ZIP;
- per-architecture Android APKs;
- the deployment bundle;
- `SHA256SUMS`.

The release tag supplies the Android application version name and a monotonic
Android version code. Configure these repository Actions secrets for
production Android signing:

- `PORTA_ANDROID_KEYSTORE_BASE64`
- `PORTA_ANDROID_KEYSTORE_PASSWORD`
- `PORTA_ANDROID_KEY_ALIAS`
- `PORTA_ANDROID_KEY_PASSWORD`

Client and server application release numbers are independent from the Porta
wire-protocol version. See [architecture.md](architecture.md#protocol-compatibility)
for the compatibility policy.
