# Development and releases

## Requirements

Go builds require Go 1.26 or newer. Android builds additionally require JDK 17,
Android SDK 35, Android NDK 27.2.12479018, and matching `gomobile` and `gobind`
binaries on `PATH`.

## Local validation

```sh
make check-version
make test-automation
make test
make test-race
make vet
make build
make build-windows
make android
```

`make test` enables the official `GODEBUG=http2xconnect=1` switch required by
the HTTP/2 Extended CONNECT integration tests.
`make test-automation` uses Python 3's standard library and Go tests to exercise
deployment, certificate sync, firewall cleanup and packaging with isolated
fixtures and mocked system commands. It does not change host services or
network settings.

For two-step QR onboarding, the focused server suite also invokes Node.js
regressions for invitation generation, dialog cleanup, fragment redemption,
and profile-copy controls:

```sh
GODEBUG=http2xconnect=1 go test ./cmd/porta-server -run 'Test(ClientAccess|ProfileQR|Portal|Admin)' -count=1
```

Run `make android` for the in-app scanner/paste parser and signed APK build.
Before shipping browser changes, exercise actual HTTPS onboarding and compact
admin dialogs at 390x844, 320x568, and 844x390. A valid first QR must open downloads
without a token prompt; only that authenticated client page shows the profile QR.
The Android camera and clipboard UI still require device acceptance.

`make test-native-mtu` separately exercises MTU feedback through a real Linux
TUN, veth pair, forwarding and NAT. It requires `ip`, `nft`, `sysctl`, and
passwordless `sudo` permission for `unshare --net`. The target compiles the
existing Go tests, enters a new network namespace, and enables
`PORTA_MTU_NATIVE_TEST=1`; the native test refuses to run in PID 1's network
namespace or a namespace with existing non-loopback interfaces. No host routes,
firewall rules, or sysctls are changed. Ordinary
Go runs skip this opt-in test; Linux CI runs the isolated target explicitly.
Do not enable the environment variable directly against host networking.

Windows networking script regressions use isolated PowerShell mocks. They run
when `pwsh` is on `PATH`, or with Windows PowerShell on Windows; otherwise those
tests are explicitly skipped. The Windows CI job runs the platform packages.
It also requires live BFE acceptance with `PORTA_WFP_NATIVE_TEST=1`, bypassing
the Go test result cache. Run the same acceptance locally from elevated Windows:

```powershell
$env:PORTA_WFP_NATIVE_TEST = "1"
go test ./internal/winnetwork -run '^TestNativeWFP' -count=1 -v
```

The native acceptance path stages the production IPv4/IPv6 filters, reads back
their schema and policy, replaces them, then **always aborts** the transaction
and checks for residual objects. It never commits a live blocking policy or
changes routes. It requires Windows/BFE and administrator access; Linux
cross-compilation cannot execute it. This is native API acceptance, not an
end-to-end packet-leak or reboot-persistence certification.

Linux binaries are written to `bin/`. The Windows target creates
`bin/porta-client-windows-amd64.zip`. Optimized per-architecture Android APKs
are written under `android/app/build/outputs/apk/release/`.

## Performance measurements

Use the existing Go benchmark runner to measure framing, packet delivery and
allocation costs:

```sh
go test ./internal/masque ./internal/protocol ./internal/tunnel \
  ./internal/usage ./internal/forwardproxy \
  -run '^$' -bench . -benchmem -count=3
```

Keep payload sizes and concurrency identical for before/after comparisons.
These in-process microbenchmarks isolate hot-path overhead; their throughput
is not a prediction of end-to-end VPN speed. Network tests should compare
HTTP/3, HTTP/2 fallback and CONNECT separately under the same latency, loss,
client count and server load.

The transport round-trip benchmark exercises the complete local HTTP/2 framed
or HTTP/3 Datagram path, including the gateway router and a fake TUN:

```sh
go test ./internal/tunnel -run '^$' \
  -bench '^BenchmarkTransportPacketRoundTrip$' -benchmem -count=3
```

For controlled impairment, `scripts/benchmark-transports.sh` builds the
loss-tolerant transport probe once and runs it in disposable network
namespaces. It reports bidirectional delivery and control-packet latency rather
than blocking when an HTTP/3 Datagram is intentionally lost. It does not alter
the host qdisc. The defaults cover 20/80/150 ms RTT, 0/0.5/1/2 percent loss,
and 20/100 Mbit/s. Override the matrix with `PORTA_BENCH_RTT_MS`,
`PORTA_BENCH_LOSS_PERCENT`, `PORTA_BENCH_RATES`, `PORTA_BENCH_PACKETS`,
`PORTA_BENCH_TIMEOUT_SECONDS`, `PORTA_BENCH_PACING_MICROS`, and
`PORTA_BENCH_COUNT`. The script requires `ip`, `tc`, `unshare`, and passwordless
`sudo`.

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

Artifacts are uploaded to a draft release before it becomes visible as a
published release. A failed upload leaves the draft unpublished and can be
retried. Published artifacts are not overwritten on workflow reruns; changes
require a new version and tag.

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
