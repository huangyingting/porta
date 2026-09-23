# Development and releases

## Requirements

Go builds require Go 1.26 or newer. Android builds additionally require JDK 17,
Android SDK 35, Android NDK 27.2.12479018, and matching `gomobile` and `gobind`
binaries on `PATH`. The Windows desktop uses the pinned Wails v3 module and
Microsoft Edge WebView2. Production builds must include the `production` build
tag; the frontend is embedded HTML, CSS, and JavaScript and does not require
Node.js or an npm build.

## Local validation

```sh
make check-version
make test-automation
make test-browser
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

`make test-native-firewall` runs the production `server-up.sh`,
`server-down.sh`, and a Go client setup/cleanup cycle inside disposable network
namespaces. It validates native
nftables parsing, atomic replacement, the IPv4/IPv6 TCP and UDP source meters,
and complete cleanup without changing the host firewall or interfaces. It
requires `ip`, `nft`, `sysctl`, `unshare`, and passwordless `sudo`.
Use `make test-native-client-network` to run only the client cycle. Its
resolver fixture also lives in an isolated mount namespace.
Both native targets set `PORTA_RUNTIME_DIRECTORY` to a private, per-test
temporary directory and clean it afterward. Network namespaces alone do not
isolate files, so the tests never use the installed service's `/run/porta`
recovery journals or an inherited runtime-directory override.

Windows networking script regressions use isolated PowerShell mocks. They run
when `pwsh` is on `PATH`, or with Windows PowerShell on Windows; otherwise those
tests are explicitly skipped. The Windows CI job runs the platform packages,
including the identity-storage handle, link rejection, and protected ACL tests.
It builds the Wails desktop with the `production` tag, smoke-tests WebView2
startup, verifies the pinned Wintun archive, and uploads the complete Windows
ZIP as a workflow artifact.
It also requires live BFE acceptance with `PORTA_WFP_NATIVE_TEST=1`, bypassing
the Go test result cache. Run the same acceptance locally from elevated Windows:

```powershell
$env:PORTA_WFP_NATIVE_TEST = "1"
$env:PORTA_WFP_NATIVE_TEST_MARKER = Join-Path $env:TEMP ("porta-wfp-" + [guid]::NewGuid())
go test ./internal/winnetwork -run '^TestNativeWFPTransactionRollback$' -count=1 -v
if ($LASTEXITCODE -ne 0 -or !(Test-Path $env:PORTA_WFP_NATIVE_TEST_MARKER)) {
  throw "Native WFP acceptance did not complete"
}
Remove-Item $env:PORTA_WFP_NATIVE_TEST_MARKER
Remove-Item Env:PORTA_WFP_NATIVE_TEST, Env:PORTA_WFP_NATIVE_TEST_MARKER
```

The native acceptance path stages the production IPv4/IPv6 filters, reads back
their schema and policy, replaces them, then **always aborts** the transaction
and checks for residual objects. It never commits a live blocking policy or
changes routes. It requires Windows/BFE and administrator access; Linux
cross-compilation cannot execute it. This is native API acceptance, not an
end-to-end packet-leak or reboot-persistence certification.
The marker is created exclusively after rollback and residual-object checks;
an existing marker or a skipped test cannot satisfy CI.

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

Ordinary branch and PR CI builds only debug APKs, named `android-debug-apks`; it receives
no release signing secrets. These developer artifacts are not release updates
and must not be copied into the download portal. Post-merge releases use
the persistent key and are the distributable update artifacts.

## Version policy

The application version is stored in `internal/buildinfo/VERSION` and currently
starts at `0.1.0`. The server, command-line clients, Windows desktop client,
Android application, mobile bridge, release metadata, and download portal all
use this application version.

During the current development series, each merged change uses the next patch
above both its base revision and existing canonical release tags:

```text
0.1.0 -> 0.1.1 -> 0.1.2
```

Keep major and minor fixed at `0.1`. PR CI compares against the PR base; `main`
push CI compares against the previous main revision. Both fetch all tags. This
prevents a lagging implementation branch from publishing a lower version than
an existing release (for example, base `0.1.29` plus published `v0.1.38` requires
`0.1.39`). A matching tag already pointing to the tested commit is excluded
from the baseline so a post-release CI rerun remains valid.
Feature-branch pushes and manual CI validate version format only.
Run `./scripts/check-version.sh HEAD` before committing an increment.
The wire-protocol version remains
independent and changes only for compatibility-breaking protocol changes.

## Continuous integration and releases

`CI` runs on every branch push (including `golang`), PRs targeting `main`, and
manual dispatches. Linux/Go, Windows and Android builds/tests must all pass.
The **PR required** check fails if any prerequisite fails, is cancelled,
or is skipped; it cannot turn a partial run into a passing merge check.
Branch, main-push and manual runs use a different **CI required** name, so
their results cannot substitute for the PR's merge validation.
PR and branch runs have separate cancellation groups, so a branch push cannot
cancel the PR's merge validation. Branch/PR CI has read-only repository
permissions and receives no release signing or VPN credentials.

`main` is protected: changes must arrive through a PR, the **PR required**
check from GitHub Actions must pass against an up-to-date base, and review
conversations must be resolved. Administrator bypass, force pushes and branch
deletion are disabled. A second human approval is not required for the
single-maintainer workflow. Do not weaken required checks to work around a
failed build or unavailable runner.

The separate **Live diagnostics** workflow runs on `main` pushes, daily, or
manually with `--ref main`. It exercises credential-free Windows and Android
TLS/authentication probes against the development gateway. Each job guards
`github.ref`; non-main manual dispatches allocate no runners (GitHub may record
a skipped run). Scheduled workflows use the default branch, which must remain
`main`. External diagnostics do not substitute for, or bypass, required CI.

The Go probe can also run locally without an account or enrolled identity:

```sh
PORTA_TLS_TEST_URL=https://porta-dev.i-csu.org:8443 \
  go test ./internal/clientapp -run '^TestLivePlatformTLSAndAuthentication$' -count=1 -v
```

It requires trusted TLS, rejects a deliberately invalid token over HTTP/3 and
HTTP/2, and checks hostname failures without downgrading. It does not establish
a VPN. Android CI uses `connectedDebugAndroidTest` with
`dev.porta.android.CertificateVerificationTest` and a nonempty
`portaTlsOrigin`; Gradle checks instrumentation results. Release trust-policy
acceptance additionally requires a signed release instrumentation build
(`-Pporta.testBuildType=release`).

The daily/manual `vpn_e2e` job in **Live diagnostics** uses the protected `development`
environment. Configure `PORTA_E2E_TOKEN` and
`PORTA_E2E_LINUX_IDENTITY_BASE64` for a dedicated test enrollment. It runs
`scripts/test-live-vpn.sh` (`make test-live-vpn`) with both transports and
collects sanitized diagnostics. Use a disposable runner: the harness creates
temporary host veth/NAT connectivity for its isolated namespace and restores
it afterward. Do not use personal identities or production credentials.
Missing secrets fail explicitly rather than silently skipping VPN acceptance.

After a PR is merged, successful **push CI on `main`** automatically starts
**Release** via `workflow_run`. Feature-branch, PR, failed, cancelled and manual
CI runs cannot publish releases. Every release job verifies the triggering
repository, branch, event and conclusion, and checks out the exact successful
CI SHA rather than whichever commit happens to be latest on `main`.

Before using signing credentials, release verifies main ancestry and rejects
an existing version tag pointing elsewhere. After builds succeed, it creates
and pushes the matching tag if needed, uploads a draft, and publishes only
after all uploads succeed. Tags do not independently trigger workflows.
Release runs are serialized and are never cancelled by a newer merge. The
workflow publishes:

- Linux AMD64 and ARM64 servers, clients, and key generators;
- the Windows desktop and CLI ZIP;
- per-architecture Android APKs;
- the deployment bundle;
- `SHA256SUMS`, its detached `SHA256SUMS.sig`, and
  `release-signing-cert.der`.

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

## Go/Rust behavioral parity

The Go 0.1.30 port was audited against immutable Rust revision
`b6e7885e0205fa81dadbc725d4fca3d5cdb0ebfb` (Rust 0.1.38).
Parity means the same supported behavior, not matching language runtimes or
application version numbers.

| Area | Go implementation |
| --- | --- |
| HTTP/3 MTU | Immutable negotiated MTU; decreasing packet budget, IPv4 fragmentation, bounded ICMP convergence and compatibility capsules |
| Backpressure/lifecycle | Independent bounded reliable queues, cancellable datagram writes, terminal-error priority and drained close |
| Diagnostics | Process-local tunnel IDs, bounded activity logs, queue/submission counters and connection-wide QUIC snapshots |
| Persistent state | Identity-specific lease reservations, committed-but-not-durable fencing, existing serialized enrollment workers and compatible state schemas |
| Linux | Explicit private identity paths, environment-only tokens, owned firewall/route recovery and ICMP feedback in both MTU modes |
| Windows | Wails localization/traffic/recovery, bounded profile storage, protected ProgramData paths and Wintun loading, native WFP, stale-packet filtering and full-ring drop accounting |
| Android | gomobile platform trust-before-proof, English/Chinese resources, certificate revocation policy, synchronized replacement and retained fail-closed recovery |
| Web/operations | Existing Go portal/admin/proxy behavior retained; signed release metadata and ticket links, isolated native/browser acceptance and live CI probes |

Go retains quic-go, Wails and gomobile, and its existing Kotlin HTTP/2 lanes.
Rust/Cargo, Quinn-specific fixes, Tauri and Rust JNI build machinery are not
ported as parallel implementations. Linux Go release binaries remain static.
Native Windows execution and authenticated Android VPN/network-switch behavior
require their platform acceptance environments; cross-builds and
credential-free TLS probes are not substitutes for those checks.
