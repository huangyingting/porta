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
make test-cascade
make test-split-tunnel
make test-subnet-router
make test-exit-selection
make test-dns-resolver
make test-admin-identity
make test-gateway-failover
make test-ipv6
make test-graceful-restart
make test-client-daemon
make test-peer-to-peer
make test-standard-masque
make test-apple-ffi
make test-service-user
make vet
make build
make build-windows
make build-linux-desktop
make android-debug
make android
```

`make build` builds the production Rust server, Linux client, and key generator
under `bin/`. Rust is the only supported implementation for shipped server and
client components.

`make test-cascade` needs passwordless `sudo`. It builds the debug server and
client, then runs `scripts/test-cascade.sh` over HTTP/3 and HTTP/2: real
gateways in network namespaces form a client -> relay -> relay -> exit chain
with identical pools. It checks the exit address seen by a web server, a
full-size DF ping, a bulk transfer, client-to-client reachability, fail-closed
behavior while the exit is down, and automatic recovery after it returns.

`make test-service-user` runs `scripts/test-service-user.sh`, which needs
systemd. It starts a relay and an exit gateway with every sandbox setting of
`deploy/porta.service` through `systemd-run`, each in a network namespace and
as an unprivileged user. It checks that the daemons hold only
`CAP_NET_ADMIN`, own their state, relay a client's traffic, and that the root
network helpers configure and remove the firewall.

`make test-subnet-router` and `make test-exit-selection` run
`scripts/test-subnet-router.sh` and `scripts/test-exit-selection.sh` over
both transports. The first routes a LAN behind one client to a client of
another account and checks access groups, allow and deny lists, and the
router's forwarding restore. The second relays one account through a default
upstream, a named exit, and the local exit, and checks that a selected exit
that is down fails closed.

`make test-dns-resolver` runs `scripts/test-dns-resolver.sh`: three clients
of two accounts use the gateway's built-in resolver, which must resolve and
reverse-resolve peer device names only, forward over UDP and TCP to a fake
upstream, refuse a blocklisted domain, and stay unreachable from outside the
tunnel.

`make test-admin-identity` runs `scripts/test-admin-identity.sh` against a
fake OpenID provider that enforces PKCE and signs RS256 ID tokens. It checks
local sign-in, TOTP enrollment and replay protection, role limits, single
sign-on for a mapped and an unknown email, that disabling an administrator
ends their session's rights, and the audit log's contents and permissions.

`make test-gateway-failover` runs `scripts/test-gateway-failover.sh` over both
transports: a client lists a primary and a faster replica, enrolls through
the primary, fails over to the replica when the primary stops, and loses its
replica session when the primary disables the account.

`make test-ipv6` runs `scripts/test-ipv6.sh` over both transports: a
dual-stack gateway's clients reach an IPv6 web server through the gateway's
NAT66 address and never through their own IPv6 network, download a large
file over IPv6, and reach each other's IPv6 addresses; an IPv4-only gateway's
full tunnel blocks IPv6 instead of leaking it; and a dual-stack split tunnel
routes only its IPv6 prefixes.

`make test-graceful-restart` runs `scripts/test-graceful-restart.sh` over both
transports: it replaces the gateway binary, sends `SIGHUP`, and checks that
the same process re-executes the new binary, keeps its TUN interface,
addresses and firewall rules, and that the client resumes within five
seconds with the same lease and transport, twice in a row.

`make test-client-daemon` runs `scripts/test-client-daemon.sh`: it drives the
Linux desktop service's control socket like the app, saving a profile,
connecting, checking traffic and the reported state, disconnecting,
reporting a rejected token, and checking that only root and the control
group may use the socket. `make build-linux-desktop` builds the window
itself (`porta-linux --features gui`); workspace builds leave it out so
they need no GTK files.

`make test-peer-to-peer` runs `scripts/test-peer-to-peer.sh`: two clients
behind separate masquerading NATs, which drop unsolicited packets like home
routers, learn each other's public addresses from a `--peer-to-peer`
gateway and punch through both NATs. The test checks that their traffic
takes the direct path, returns to the gateway when the path is blocked and
goes direct again when it heals, and that a device disconnecting ends its
peers' paths to it.

`make test-standard-masque` builds the interop probe in
`experiments/masque-interop` (Go, using the independent quic-go/connect-ip-go
CONNECT-IP client; it is test tooling and the only Go in the repository) and
runs `scripts/test-standard-masque.sh`: the probe is refused until the
account allows standard clients, then receives an address and routes with or
without asking and pings the gateway and an Internet host through the tunnel.

`make test-apple-ffi` links `rust/porta-apple/tests/probe.c` against
`libporta.a` and runs `scripts/test-apple-ffi.sh`: through the C interface
the macOS and iOS apps use, the probe connects with a device proof, reads the
session's settings, pings through the tunnel and cancels; a wrong token is
reported as denied. On macOS with Xcode, `make build-apple` builds
`apple/build/Porta.xcframework` and `make test-apple` runs PortaKit's Swift
tests and an iOS build.

`make test-split-tunnel` runs `scripts/test-split-tunnel.sh` the same way. A
gateway advertises one private prefix and a DNS domain; the test checks that
only that prefix uses the tunnel, other traffic goes direct, DNS is scoped to
the domain, the prefix fails closed rather than leaking while the gateway is
down, and disconnecting restores the host's routing.

`make test-automation` uses Python 3's standard library to exercise
deployment, certificate sync, firewall cleanup and packaging with isolated
fixtures and mocked system commands. It does not change host services or
network settings.

The workspace patches `quinn-proto` for all server and native client builds.
The locked upstream `0.11.17` release double-counts evicted datagrams, causing
queue accounting to underflow and panic under sustained send pressure.
The vendored copy carries the exact upstream backport; see
[`rust/porta-server/vendor/README.md`](../rust/porta-server/vendor/README.md).
The focused end-to-end queue regression is:

```sh
cargo test --manifest-path rust/Cargo.toml --locked \
  --package porta-client-rust --test quic_datagrams
```

`make test` also covers shared IPv4 fragmentation/ICMP rules, changing HTTP/3
packet budgets, unsent-only retries, bounded DF compatibility and negotiated
receive ceilings. Transport loopbacks exercise real QUIC capacity limits,
client-local ICMP delivery, control ordering, blocked reliable writers,
deadlines and cancellation. Deterministic capacity changes cover reductions
after setup; these regressions do not claim to reproduce every WAN loss pattern.

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

The separate **Live diagnostics** workflow runs the same credential-free native
Windows and Android emulator probes against `https://porta-dev.i-csu.org:8443`
every day and after `main` pushes. Use its **Run workflow** action with
`--ref main` for an additional run. Every live job rejects other refs.
The live jobs validate platform trust, HTTP/2 and HTTP/3
negotiation, and rejection of an invalid account before enrollment. They do not
establish a VPN, modify runner routes, consume a device slot, or replace physical
device testing of the full VPN data path.

Live diagnostics also runs a credentialed Linux full-tunnel test every day.
Use its **Run workflow** action on `main` with `vpn_e2e` enabled for another run.
The `vpn-e2e-linux` job is attached to the branch-restricted `development`
environment and reads two environment secrets:

- `PORTA_E2E_TOKEN` is the token for a dedicated client limited to one device.
- `PORTA_E2E_LINUX_IDENTITY_BASE64` is that device's fixed private identity file.

The identity is reused so scheduled runs do not consume additional persistent
device slots. The test starts the production Linux client with both HTTP/3 and
HTTP/2 inside a disposable network namespace. It applies real TUN routes and
nftables leak protection, adds temporary forwarding accepts scoped to the test
veth, confirms that `10.66.0.1` is unreachable before connection, verifies the
route uses the Porta TUN, exchanges normal ICMP and a don't-fragment payload
sized to the negotiated TUN MTU and capped at 1,200 bytes, then stops the client
and requires the TUN, recovery journal, routes, leak-protection table, and
gateway reachability to disappear. The forwarding rules are removed with the
namespace. Only `resolvectl` is replaced by a namespace-local adapter because
the host's systemd-resolved instance cannot see interfaces inside the disposable
namespace.

Run the same test locally after supplying the two protected values:

```sh
PORTA_E2E_TOKEN='...' \
PORTA_E2E_LINUX_IDENTITY_BASE64='...' \
  make test-live-vpn
```

When running the test on the development server itself, set
`PORTA_E2E_SERVER_ADDRESS=192.0.2.1` to reach its listener through the test
namespace's host-side veth while preserving normal hostname and certificate
validation. Hosted CI leaves this unset and resolves the public server address.

Never expose these values to pull-request jobs or store the development server's
admin token in GitHub. The CI account and identity are dedicated to this test;
rotating either one requires removing the old enrolled device and updating both
environment secrets together.

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
and must not be copied into the download portal. Post-merge releases use
the persistent key and are the distributable update artifacts.

## Version policy

The application version is stored in `internal/buildinfo/VERSION` and currently
starts at `0.1.0`. The server, command-line clients, Windows desktop client,
Android application, native Rust libraries, release metadata, and download portal all
use this application version.

During the current development series, each promoted change uses the next patch
above both its base revision and existing canonical release tags:

```text
0.1.0 -> 0.1.1 -> 0.1.2
```

Keep major and minor fixed at `0.1`. PR CI compares the PR base and all release
tags; `main` push CI compares the previous main revision and all release tags.
This lets a lagging main promote Rust without reusing an already published
version: base `0.1.29` and tag `v0.1.38` require `0.1.39`. The tested commit's
own matching tag is excluded to permit CI reruns after publication.
Feature-branch pushes and manual CI validate version format only.
Run `./scripts/check-version.sh origin/main` before promoting Rust and keep all
Porta Cargo package versions synchronized with `internal/buildinfo/VERSION`.
The wire-protocol version remains
independent and changes only for compatibility-breaking protocol changes.

## Continuous integration and releases

The promotion path is **`rust` -> `main`**. `main` is downstream of Rust and
retains its Cargo, Tauri, Rust Android/JNI, native WFP, and Linux glibc-baseline
workflows. `golang` is a separate implementation branch; do not merge its Go
build/release workflows into `main`.

**CI** builds and tests branch pushes, PRs targeting `main`, and manual runs.
Linux/Rust, the standard CONNECT-IP interop job, the macOS job that builds
and tests PortaKit, native Windows, and Android must all pass. The stable
**Rust PR required** check rejects failed, cancelled or skipped jobs and rejects
promotion PRs whose source is not this repository's `rust` branch. Branch/main
and manual runs use **Rust CI required**, so they cannot substitute for the
PR merge check. Branch and PR runs have separate cancellation groups.

`main` requires an up-to-date **Rust PR required** result from GitHub Actions,
a PR, and resolved conversations. Administrator bypass, force pushes and
deletion are disabled. A second human approval is not required for this
single-maintainer workflow. After promotion, sync the main merge commit back
into `rust` before its next promotion, without replacing Rust-specific tooling.

After merging the promotion PR, successful **push CI on `main`** triggers
**Release** through `workflow_run`. Feature-branch, PR, failed, cancelled, and
manual CI runs cannot publish. Release validates the triggering repository,
event, branch and result and checks out the exact successful CI SHA, not the
latest main head. Before signing, it checks main ancestry and rejects an
existing version tag pointing elsewhere. After builds succeed, it creates the
tag if needed, uploads a draft and publishes only after all uploads succeed.
Release runs are serialized without cancellation; tag pushes do not trigger
workflows. **Live diagnostics** remains separate and main-only.

The release workflow publishes:

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
