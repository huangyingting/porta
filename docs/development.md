# Development and releases

## Requirements

Go builds require Go 1.26 or newer. Android builds additionally require JDK 17,
Android SDK 35, Android NDK 27.2.12479018, and matching `gomobile` and `gobind`
binaries on `PATH`.

## Local validation

```sh
make check-version
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

## Version policy

The application version is stored in `internal/buildinfo/VERSION` and currently
starts at `0.1.0`. The server, command-line clients, Windows desktop client,
Android application, mobile bridge, release metadata, and download portal all
use this application version.

During the current development series, every merged change increments exactly
the patch component:

```text
0.1.0 -> 0.1.1 -> 0.1.2
```

Keep major and minor fixed at `0.1`. CI checks the version against the pull
request base or previous pushed revision. The wire-protocol version remains
independent and changes only for compatibility-breaking protocol changes.

## Continuous integration and releases

CI runs automatically for pushes and pull requests and can also be started
manually. A tag matching the source version, such as `v0.1.0`, runs the release
workflow and publishes:

- Linux AMD64 and ARM64 servers, clients, and key generators;
- the Windows desktop and CLI ZIP;
- per-architecture Android APKs;
- the deployment bundle;
- `SHA256SUMS`.

The release version supplies the Android application version name and a
monotonic Android version code. Configure these repository Actions secrets for
production Android signing:

- `PORTA_ANDROID_KEYSTORE_BASE64`
- `PORTA_ANDROID_KEYSTORE_PASSWORD`
- `PORTA_ANDROID_KEY_ALIAS`
- `PORTA_ANDROID_KEY_PASSWORD`

Client and server application release numbers are independent from the Porta
wire-protocol version. See [architecture.md](architecture.md#protocol-compatibility)
for the compatibility policy.
