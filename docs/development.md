# Development and releases

## Requirements

All shipped binaries use the stable Rust toolchain with Cargo, Clippy, and
rustfmt. Android builds additionally require JDK 17, Android SDK 35, and Android
NDK 27.2.12479018. Distributable Windows builds use the MSVC Rust target on
Windows; Linux cross-build checks use `x86_64-pc-windows-gnu` and MinGW-w64.
The Tauri 2 desktop
uses Microsoft Edge WebView2. Its embedded HTML, CSS, and JavaScript require no
Node.js or npm build.

## Local validation

```sh
make check-version
make test-automation
make test
make test-rust-server
make test-rust-client
make test-rust-interop
make test-windows-cross
make test-native-firewall
make vet
make build
make build-windows
make android-debug
make android
```

`make build` builds the production Rust server, Linux client, and key generator
under `bin/`. Rust is the only supported implementation for shipped server and
client components.

`make test-automation` uses Python 3's standard library to exercise
deployment, certificate sync, firewall cleanup and packaging with isolated
fixtures and mocked system commands. It does not change host services or
network settings.

The server and desktop suites also use Node.js, when available, to syntax-check
the embedded browser JavaScript:

```sh
make test-server-web
```

Run `make android` for the in-app scanner/paste parser and signed APK build.
Before shipping browser changes, exercise actual HTTPS onboarding and compact
admin dialogs at 390x844, 320x568, and 844x390. A valid first QR must open downloads
without a token prompt; only that authenticated client page shows the profile QR.
The Android camera and clipboard UI still require device acceptance.

### Certificate integration probes

Android uses the platform certificate verifier. Its network policy permits HTTP
only for Let's Encrypt's public, issuer-signed CRLs under `c.lencr.org`; all other
application traffic remains HTTPS-only. This enables CRL fallback for certificates
without an OCSP responder rather than ignoring a revocation failure. The network
configuration uses system trust anchors and enables user-CA overrides only for
debuggable builds.
Porta's own process is excluded from its VPN so platform certificate fetches can
complete during reconnects, while other applications remain routed through the VPN.

Run the policy and live certificate regressions on an Android device or emulator:

```sh
cd android
ANDROID_SERIAL=emulator-5680 ./gradlew connectedDebugAndroidTest \
  -Pandroid.testInstrumentationRunnerArguments.class=dev.porta.android.CertificateVerificationTest \
  -Pandroid.testInstrumentationRunnerArguments.portaTlsOrigin=https://porta-dev.i-csu.org:8443
```

Use `-Pporta.testBuildType=release connectedReleaseAndroidTest` instead to exercise
the signed, minified release APK. The live probes verify the certificate and the
Rust TLS handshake without enrolling a VPN device, and reject expired and altered
certificates. `portaTlsOrigin` is required for the live probes. To run only the
offline policy assertion, select
`CertificateVerificationTest#testCleartextIsRestrictedToPublicCertificateRevocationHosts`.

Linux and Windows use separate platform-verifier backends. Run their opt-in
TCP/HTTP2 and QUIC/HTTP3 certificate probe with `PORTA_TLS_TEST_URL` set to the
gateway URL:

```sh
PORTA_TLS_TEST_URL=https://porta-dev.i-csu.org:8443 \
  cargo test --manifest-path rust/Cargo.toml --package porta-client-rust \
  --test platform_tls --locked -- --ignored --nocapture
```

This probe does not create a TUN, modify routes, or enroll a device. Execute it
natively on Windows to exercise Windows certificate APIs; cross-compilation alone
does not validate the Windows trust store.

CI runs the same credential-free native Windows and Android emulator probes
against `https://porta-dev.i-csu.org:8443` every day and after default-branch
pushes. Use the **Run workflow** action with `live_clients` enabled to
test another branch. The live jobs validate platform trust, HTTP/2 and HTTP/3
negotiation, and rejection of an invalid account before enrollment. They do not
establish a VPN, modify runner routes, consume a device slot, or replace physical
device testing of the full VPN data path.

`make test-native-firewall` runs the production `server-up.sh` and
`server-down.sh` inside a disposable network namespace. It validates native
nftables parsing, atomic replacement, the IPv4/IPv6 TCP and UDP source meters,
automatic-MTU sysctls on only the owned TUN interface, and complete cleanup
without changing the host firewall or interfaces. It requires `ip`, `nft`,
`sysctl`, `unshare`, and passwordless `sudo`. The test sets
`PORTA_RUNTIME_DIRECTORY` to a private, per-test temporary directory and cleans
it afterward. Network namespaces alone do not isolate files, so the test never
uses the installed service's `/run/porta` recovery journals or an inherited
runtime-directory override. Rust unit tests separately verify fragmentation and
ICMP generation.

The Windows CI job runs the Rust platform tests, including identity/profile
DPAPI compatibility, private-file validation, journal recovery, and native WFP
transaction acceptance. It builds the Tauri desktop, smoke-tests WebView2
startup, verifies the pinned Wintun archive, and uploads the complete Windows
ZIP as a workflow artifact. Run the same acceptance locally from elevated
Windows:

```powershell
$env:PORTA_WFP_NATIVE_TEST = "1"
cargo test --manifest-path rust/Cargo.toml --locked `
  --target x86_64-pc-windows-msvc `
  --package porta-client-rust -- --nocapture
```

The native acceptance path stages the production IPv4/IPv6 filters, reads back
their schema and policy, replaces them, then **always aborts** the transaction
and checks for residual objects. It never commits a live blocking policy or
changes routes. It requires Windows/BFE and administrator access; Linux
cross-compilation cannot execute it. This is native API acceptance, not an
end-to-end packet-leak or reboot-persistence certification.

Linux binaries are written to `bin/`. `make build-windows` cross-compiles the
Windows applications for validation; the distributable ZIP is built with MSVC
by Windows CI and the release workflow so WebView2Loader is statically linked.
Optimized per-architecture Android APKs are written under
`android/app/build/outputs/apk/release/`.

## Performance measurements

Keep payload sizes and concurrency identical for before/after comparisons.
Network tests should compare HTTP/3, HTTP/2 fallback, and automatic transport
selection separately under the same latency, loss, client count, and server
load.

For complete HTTP/2 and HTTP/3 measurements through the production Rust
server, real TUN, kernel UDP echo path, and production Rust client stack, run:

```sh
PORTA_SERVER_BENCH_WORK=/path/out ./experiments/server-benchmark/run.sh
```

`make test-rust-interop` runs a short form of this benchmark across HTTP/2,
HTTP/3, and automatic transport with automatic MTU enabled. The benchmark
requires `ip`, `nft`, `unshare`, GNU time, and passwordless `sudo`, and runs
entirely in a disposable network namespace. Set
`PORTA_SERVER_BENCH_LOADGENS` to compare labeled Rust and preserved baseline
executables in one interleaved run.

## Android signing

All distributed Android release APKs use one persistent signing identity,
pinned by the public certificate fingerprint in
`android/signing-certificate.sha256`. Release tasks reject missing or partial
credentials, missing keys, incorrect passwords, and a different certificate.
They never fall back to a machine-generated debug key.

Local builds read a private configuration file by default:

```text
~/.config/porta/android-signing/signing.properties
```

If `XDG_CONFIG_HOME` is set, it replaces `~/.config`. Set
`PORTA_ANDROID_SIGNING_PROPERTIES` to use another private configuration file.
The file contains:

```properties
storeFile=keystore.p12
storePassword=<saved keystore password>
keyAlias=porta
keyPassword=<saved private-key password>
```

A relative `storeFile` is resolved beside this properties file. Restore both
files from a secure backup; **do not generate a replacement key on a new
machine**. Keep the signing directory private (mode 0700) and the keystore and
properties file readable only by their owner (mode 0600). `make android` then
uses this identity automatically.

CI releases use the same keystore through four environment variables. All four
must be provided together; partial environment configuration does not borrow
values from the local file:

```sh
export PORTA_ANDROID_KEYSTORE=/secure/path/keystore.p12
export PORTA_ANDROID_KEYSTORE_PASSWORD='...'
export PORTA_ANDROID_KEY_ALIAS=porta
export PORTA_ANDROID_KEY_PASSWORD='...'
make android
```

Do not commit a keystore or its passwords. Only the public fingerprint belongs
in Git. The release workflow verifies every produced APK against that
fingerprint before publication and removes its temporary key afterward.
Back up the private signing directory securely: GitHub Actions secrets cannot
be downloaded later as a recovery mechanism.

The persistent identity preserves the development APK distributed as 0.1.6.
Older portal APKs used a different machine-generated debug key. Without that
older private key, this cannot retroactively make those installations accept
an in-place update; that migration still requires saving profile/token details
and reinstalling once. Subsequent release builds retain the fixed identity.
This preserves a development signer; managed Play App Signing for future
public distribution needs a deliberate signing/migration plan.

Ordinary PR CI builds only debug APKs, named `android-debug-apks`; it receives
no release signing secrets. These developer artifacts are not release updates
and must not be copied into the download portal. Tag-triggered releases use
the persistent key and are the distributable update artifacts.

## Version policy

The application version is stored in `internal/buildinfo/VERSION` and currently
starts at `0.1.0`. The server, command-line clients, Windows desktop client,
Android application, native Rust libraries, release metadata, and download portal all
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
- `SHA256SUMS`, `SHA256SUMS.sig`, and `release-signing-cert.der`.

Artifacts are uploaded to a draft release before it becomes visible as a
published release. A failed upload leaves the draft unpublished and can be
retried. Published artifacts are not overwritten on workflow reruns; changes
require a new version and tag.

Each release also publishes `SHA256SUMS`, its detached `SHA256SUMS.sig`, and
`release-signing-cert.der`. The workflow verifies that the certificate matches
the repository pin before signing, and deployment verifies the pin and
signature before trusting any downloaded artifact hash.

The release version supplies the Android application version name and a
monotonic Android version code. These repository Actions secrets must contain
the same persistent signing identity used locally:

- `PORTA_ANDROID_KEYSTORE_BASE64`
- `PORTA_ANDROID_KEYSTORE_PASSWORD`
- `PORTA_ANDROID_KEY_ALIAS`
- `PORTA_ANDROID_KEY_PASSWORD`

Missing signing secrets fail the release workflow instead of publishing an
APK signed with a newly generated debug key. Updating a password or moving
the keystore must not change the certificate pin or signing identity.

Client and server application release numbers are independent from the Porta
wire-protocol version. See [architecture.md](architecture.md#protocol-compatibility)
for the compatibility policy.
