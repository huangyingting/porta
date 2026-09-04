# Porta

Porta is a production-oriented, auditable IPv4 VPN and authenticated forward
proxy implementing MASQUE `CONNECT-IP` (RFC 9484). The gateway accepts HTTP/2
over TCP and HTTP/3 over QUIC/UDP on the same port. The repository includes a
Linux gateway, a Windows Wintun client, and an Android `VpnService` client.

It is designed for authorized remote access and compatibility with standard
HTTP infrastructure. Ordinary browser visits receive a compact, neutral Porta
studio page, while operational endpoints remain isolated on the loopback admin
listener. Read
[the threat model](docs/threat-model.md) before deployment.

## Production capabilities

- RFC 9484 Extended CONNECT with `:protocol=connect-ip`
- ADDRESS_REQUEST, ADDRESS_ASSIGN, and ROUTE_ADVERTISEMENT capsules
- HTTP/3 IP packets in QUIC Datagrams with Context ID 0
- HTTP/2 and HTTP/3-without-Datagram fallback using RFC 9297 DATAGRAM capsules
- Bearer authentication, per-client IPv4 `/32` leases, and source validation
- One Linux TUN interface with bounded per-client receive queues
- Durable per-client lease state across planned gateway restarts
- Client accounts with hashed tokens and configurable multi-device limits
- Authenticated Prometheus metrics
- Compact neutral Porta studio page for ordinary public HTTP requests
- Optional authenticated HTTPS CONNECT proxy on the same TLS listener
- Windows Wintun client plus explicit route setup/teardown scripts
- Android native HTTP/3 MASQUE `VpnService` client with four-lane HTTP/2 fallback
- Real bidirectional HTTP/2 Extended CONNECT and HTTP/3 Datagram tests

Desktop clients use MASQUE exclusively. Android uses MASQUE over HTTP/3 when
available and a required four-lane `POST /v1/tunnel` transport over HTTP/2
because OkHttp does not expose the Extended CONNECT pseudo-header required by
`CONNECT-IP`. Details are in [the architecture document](docs/architecture.md).

## Build and test

Requirements are Go 1.26 or newer. Android builds additionally require JDK 17,
Android SDK 35, Android NDK 27.2.12479018, and matching `gomobile` and `gobind`
binaries on `PATH`.

```sh
make test
make test-race
make vet
make build
make build-windows
make android
```

`make test` enables the official `GODEBUG=http2xconnect=1` switch so the
HTTP/2 Extended CONNECT integration test runs instead of being skipped.

Optimized Android APKs are written to
`android/app/build/outputs/apk/release/`, one per CPU architecture. The ARM64
APK is the normal choice for current physical Android devices.

## One-click production deployment

GitHub Releases are the distribution source. Download the small deployment
bundle and its checksum, then let the script fetch and verify the current
server binary:

```sh
gh release download latest --repo huangyingting/porta \
  --pattern porta-deploy.tar.gz --pattern SHA256SUMS
grep ' porta-deploy.tar.gz$' SHA256SUMS | sha256sum -c -
tar -xzf porta-deploy.tar.gz
cd porta
export GH_TOKEN=$(gh auth token)
```

The repository is private, so the GitHub CLI must be authenticated with an
account that can read it. The token is used only for the release download and
is not written to Porta's configuration.

For a standalone Linux server, deploy direct HTTP/2 and HTTP/3 on TCP and UDP
443 with automatic Let's Encrypt issuance:

```sh
sudo --preserve-env=GH_TOKEN ./scripts/deploy.sh \
  --domain vpn.example.com \
  --acme-email admin@example.com
```

Public TCP port 80 must reach Porta for the HTTP-01 challenge. If another web
server already owns ports 80 and 443, use an externally managed certificate
and choose another direct port:

```sh
sudo --preserve-env=GH_TOKEN ./scripts/deploy.sh \
  --domain vpn.example.com \
  --cert /absolute/path/vpn.example.com.crt \
  --key /absolute/path/vpn.example.com.key \
  --port 8443
```

The command downloads the matching `porta-server` release binary, verifies it
against the release checksum, installs it, creates credentials on first use,
configures systemd, TLS issuance or certificate synchronization, QUIC socket
buffers, forwarding, and NAT, then verifies the TLS readiness endpoint. It
preserves credentials and leases when run again for an upgrade and rolls back
the service configuration if deployment fails. It does not modify reverse
proxy configuration or cloud firewall rules.

See [the production deployment guide](docs/deployment.md) for prerequisites,
custom ports and networks, reverse-proxy fallback, firewall rules, credentials,
validation, Android setup, and removal.

## Forward proxy

The authenticated HTTPS CONNECT proxy is enabled by default:

```sh
sudo --preserve-env=GH_TOKEN ./scripts/deploy.sh \
  --domain vpn.example.com \
  --cert /absolute/path/vpn.example.com.crt \
  --key /absolute/path/vpn.example.com.key \
  --port 8443
```

Pass `--disable-forward-proxy` only when the deployment should provide VPN
service without the proxy.

The proxy reuses Porta client accounts. Use a stable device ID as the Basic
username and that client's token as the password:

```sh
curl --proxy https://vpn.example.com:8443 \
  --proxy-basic --proxy-user 'laptop:CLIENT_TOKEN' \
  https://example.com/
```

Only HTTPS `CONNECT` is supported, including HTTP/2 CONNECT streams. Porta
rejects ordinary HTTP proxy requests and every destination port except 443.
Loopback, private, link-local, metadata, multicast, documentation, benchmark,
and other non-public addresses are rejected after DNS resolution. Porta returns
a standard `407 Proxy Authentication Required` challenge only for CONNECT
requests so browser extensions can supply stored credentials. Ordinary requests
without valid credentials still fall through to the normal landing or
unsupported-request behavior. Porta does not publish a PAC file and does not
cache responses.

For ZeroOmega, select an **HTTPS proxy**, use the Porta hostname and port, set a
stable device ID such as `chrome-zeroomega` as the username, and use the
client token as the password. ZeroOmega supplies those credentials after
Porta's CONNECT-only authentication challenge.

## Client downloads

The same release publishes direct client downloads:

- Linux x86-64: `porta-client-linux-amd64`
- Linux ARM64: `porta-client-linux-arm64`
- Windows x86-64: `porta-client-windows-amd64.zip` (desktop UI, CLI, and elevated network helper)
- Android: `porta-android-arm64-v8a.apk`, `porta-android-armeabi-v7a.apk`, or
  `porta-android-x86_64.apk`

Release deployments also mirror these files onto the Porta server, so clients
do not need GitHub access:

```text
https://vpn.example.com/download/porta-client-linux-amd64
https://vpn.example.com/download/porta-client-linux-arm64
https://vpn.example.com/download/porta-client-windows-amd64.zip
https://vpn.example.com/download/porta-android-arm64-v8a.apk
https://vpn.example.com/download/porta-android-armeabi-v7a.apk
https://vpn.example.com/download/porta-android-x86_64.apk
https://vpn.example.com/download/SHA256SUMS
```

Include the configured port in the URL when Porta does not listen on 443.
Only these exact filenames are served; the landing page does not advertise or
link to them. Authenticated GitHub release downloads remain available as a
fallback.

## Gateway

Use separate random bootstrap, admin, and metrics tokens. The bootstrap token
creates the first client account only when the registry does not yet exist.
Pass tokens through the environment so they do not appear in the process list.
The server obtains and renews its certificate through Let's Encrypt. Point the
domain's A/AAAA record at the gateway, expose TCP port 80 for the HTTP-01
challenge, and expose TCP and UDP port 443:

```sh
export PORTA_TOKEN="replace-with-a-random-32-byte-or-longer-secret"
export PORTA_ADMIN_TOKEN="use-a-different-random-admin-secret"
export PORTA_METRICS_TOKEN="use-a-different-random-secret"
sudo --preserve-env=PORTA_TOKEN,PORTA_ADMIN_TOKEN,PORTA_METRICS_TOKEN ./bin/porta-server \
  --listen :443 \
  --admin-listen 127.0.0.1:9090 \
  --acme-domain vpn.example.com \
  --acme-email admin@example.com \
  --acme-cache /var/lib/porta/acme \
  --acme-http-listen :80 \
  --client-registry /var/lib/porta/clients.json \
  --usage-state /var/lib/porta/usage.json \
  --interface porta0 \
  --pool 10.66.0.0/24 \
  --dns 1.1.1.1 \
  --mtu 1100
```

The loopback admin UI is a compact operational console for client accounts and
devices. It shows live logical sessions, persisted upload/download totals,
connection counts, current transport and assigned address, recent activity,
capacity and stale-account warnings, with search, filters, sorting, and
expandable device diagnostics. It also manages tokens, device limits, enabled
state, and enrolled devices without restarting Porta. Usage is checkpointed to
`usage.json` beside the client registry by default. Tokens are generated with
32 random bytes, stored only as SHA-256 hashes, and displayed once when created
or rotated. One client token may be used by several device IDs up to that
client's configured limit.

The daemon creates `porta0`, but deliberately does not modify forwarding or
firewall state. In another root shell, after reviewing the script, configure
the interface and NAT. Replace `eth0` with the real egress interface:

```sh
sudo ./scripts/server-up.sh porta0 10.66.0.1/24 10.66.0.0/24 eth0
```

Open both TCP and UDP port 443 at the host and cloud firewalls. Tear down only
the nftables table owned by this project with:

```sh
sudo ./scripts/server-down.sh porta0 eth0
```

When Docker's `DOCKER-USER` chain is present, the setup script also installs
the two forwarding exceptions required for `porta0`. Passing the external
interface to the teardown script removes those exceptions.

The current Go HTTP/2 implementation gates Extended CONNECT behind the
official `GODEBUG=http2xconnect=1` compatibility switch. `porta-server` detects
its absence and re-executes itself once with that switch enabled while
preserving existing `GODEBUG` values.

The cache directory persists the ACME account and certificates across
restarts; keep it private and durable. To use TLS-ALPN-01 instead of opening
port 80, pass an empty `--acme-http-listen`; the gateway's TCP listener must
then be publicly reachable on port 443. Certificate issuance occurs on the
first TLS request for the configured domain, and renewal is automatic.

For production, use a service manager, an unprivileged process with narrowly
scoped TUN and low-port capabilities, credential rotation, and gateway egress
controls.

Ordinary browser requests receive a neutral Porta studio page by default.
`/healthz`, `/readyz`, `/metrics`, and the admin UI are not exposed on the
public tunnel listener. They are available only from the loopback listener at
`127.0.0.1:9090` by default. Reach the UI through an SSH tunnel and open
`http://127.0.0.1:9090`; API data requires `PORTA_ADMIN_TOKEN`. Use
`--landing-page=false` only when an API-style 404 is preferred over the landing
page.

### Direct HTTP/3 alongside an existing web server

When another web server already owns port 443, run Porta directly on another
public port, such as 8443. The existing service can continue managing the
domain certificate and serving web traffic on 443, while tunnel traffic
connects directly to Porta over TCP and UDP 8443:

```sh
sudo ./bin/porta-server \
  --listen :8443 \
  --tls-cert /etc/porta/tls/server.crt \
  --tls-key /etc/porta/tls/server.key \
  --client-registry /var/lib/porta/clients.json \
  --interface porta0 \
  --pool 10.66.0.0/24 \
  --dns 1.1.1.1 \
  --mtu 1100
```

Open both TCP and UDP 8443 in the host and cloud firewalls. HTTP/2 uses the
TCP listener and HTTP/3/MASQUE uses the UDP listener. For good QUIC throughput,
install the included socket-buffer limits:

```sh
sudo install -m 0644 deploy/99-porta-quic.conf /etc/sysctl.d/99-porta-quic.conf
sudo sysctl --system
```

The static TLS loader detects atomically replaced certificate files during
new TLS handshakes, so the gateway does not need a restart solely to load a
renewed certificate. If another service owns certificate renewal, do not grant
the hardened Porta process access to its private storage. Instead, use the
included root-run certificate synchronization timer:

```sh
sudo install -d -m 0755 /usr/local/libexec/porta
sudo install -m 0755 scripts/sync-cert.sh /usr/local/libexec/porta/
sudo install -m 0644 deploy/porta-cert-sync.service deploy/porta-cert-sync.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl start porta-cert-sync.service
sudo systemctl enable --now porta-cert-sync.timer
```

Adjust the source certificate and key paths in `porta-cert-sync.service` for
the domain before installing it. The synchronization script validates that the
certificate and private key match and replaces both destination files. Porta
loads the renewed pair on subsequent TLS handshakes without disconnecting
active tunnels.

An existing reverse proxy may retain a compatibility endpoint on 443 by
forwarding HTTP/2 requests to Porta's TLS listener with response buffering
disabled and TLS server name `vpn.example.com`. This carries only the HTTP/2
fallback; native HTTP/3/MASQUE clients connect directly to UDP 8443.

Check the direct TLS listener locally without disabling certificate
verification:

```sh
curl http://127.0.0.1:9090/readyz
curl --resolve vpn.example.com:8443:127.0.0.1 \
  -H "Authorization: Bearer $PORTA_METRICS_TOKEN" \
  http://127.0.0.1:9090/metrics
```

### Behind a reverse proxy

Use `--behind-proxy` when a reverse proxy terminates TLS and manages the public
certificate. Porta then serves plaintext HTTP/2 (h2c) on its
TCP listener and does not start ACME, TLS, or HTTP/3 listeners. Bind the
backend to loopback so it cannot be reached directly:

```sh
export PORTA_TOKEN="replace-with-a-random-32-byte-or-longer-secret"
export PORTA_ADMIN_TOKEN="use-a-different-random-admin-secret"
sudo --preserve-env=PORTA_TOKEN,PORTA_ADMIN_TOKEN ./bin/porta-server \
  --behind-proxy \
  --listen 127.0.0.1:8443 \
  --admin-listen 127.0.0.1:9090 \
  --client-registry /var/lib/porta/clients.json \
  --interface porta0 \
  --pool 10.66.0.0/24 \
  --dns 1.1.1.1 \
  --mtu 1100
```

Configure the reverse proxy to use HTTP/2 cleartext for the loopback backend,
disable response buffering, and keep `/metrics` inaccessible publicly.

The repository includes `deploy/porta.service` for a persistent direct TLS
deployment on TCP and UDP 8443 using `eth0` as the external interface. Adjust
the domain-specific certificate synchronization unit and network values before
installing:

```sh
make build
sudo install -m 0755 bin/porta-server /usr/local/bin/porta-server
sudo install -d -m 0755 /usr/local/libexec/porta /etc/porta
sudo install -m 0755 scripts/server-up.sh scripts/server-down.sh scripts/sync-cert.sh /usr/local/libexec/porta/
{
  printf 'PORTA_TOKEN=%s\n' "$(openssl rand -hex 32)"
  printf 'PORTA_ADMIN_TOKEN=%s\n' "$(openssl rand -hex 32)"
  printf 'PORTA_METRICS_TOKEN=%s\n' "$(openssl rand -hex 32)"
} | sudo tee /etc/porta/porta.env >/dev/null
sudo chmod 0600 /etc/porta/porta.env
sudo install -m 0644 deploy/porta.service deploy/porta-cert-sync.service deploy/porta-cert-sync.timer /etc/systemd/system/
sudo install -m 0644 deploy/99-porta-quic.conf /etc/sysctl.d/99-porta-quic.conf
sudo sysctl --system
sudo systemctl daemon-reload
sudo systemctl start porta-cert-sync.service
sudo systemctl enable --now porta
sudo systemctl enable --now porta-cert-sync.timer
```

Validate the direct listener after deployment:

```sh
curl http://127.0.0.1:9090/healthz
```

Operational checks:

```sh
systemctl status porta
journalctl -u porta -f
curl http://127.0.0.1:9090/readyz
ADMIN_TOKEN="$(sudo sed -n 's/^PORTA_ADMIN_TOKEN=//p' /etc/porta/porta.env)"
curl -H "Authorization: Bearer $ADMIN_TOKEN" http://127.0.0.1:9090/api/clients
METRICS_TOKEN="$(sudo sed -n 's/^PORTA_METRICS_TOKEN=//p' /etc/porta/porta.env)"
# This loopback HTTP check applies only to the --behind-proxy h2c deployment.
curl -H "Authorization: Bearer $METRICS_TOKEN" http://127.0.0.1:9090/metrics
```

To upgrade, build and install the new server binary, then restart the service.
Connected Android clients reconnect automatically with bounded backoff. They
retain the VPN interface when the restarted server assigns the same lease; if
the lease changes, Android safely replaces the interface and existing flows
reconnect:

```sh
make build
sudo install -m 0755 bin/porta-server /usr/local/bin/porta-server
sudo systemctl restart porta
```

Standard HTTP reverse proxies do not preserve MASQUE `CONNECT-IP` or proxy
QUIC datagrams to the backend. Android can use its four-lane HTTP/2 fallback
through a proxy that streams request and response bodies without buffering.
Desktop clients require direct standards-based MASQUE connectivity.

The desktop client keeps its TUN interface open and reconnects an interrupted
established session with bounded exponential backoff. It exits if the server
assigns a different lease or MTU because existing operating-system routes
would no longer be valid. Use `--reconnect=false` to retain one-shot behavior
or `--reconnect-max-delay` to change the retry ceiling. Initial configuration
or authentication failures still return immediately.

Run Porta directly when HTTP/3 or standards-based MASQUE transport is required.

## Windows client

The Windows release ZIP includes the official signed AMD64 `wintun.dll` from
[Wintun](https://www.wintun.net/) beside `porta.exe` and `porta-cli.exe`. The
build verifies the pinned upstream archive checksum before
packaging it.

Launch `porta.exe` for the default desktop experience. It stores multiple
profiles under the current Windows account, protects client tokens with DPAPI,
shows connection state, assigned address, duration, traffic totals, reconnect
activity, and a bounded diagnostic log. Windows requests administrator access
when the desktop client starts because Wintun adapter ownership and route
changes require elevation. Route ownership state is recorded so disconnect or
a later connection removes only Porta-created routes and can clean up an
interrupted process.

Use `porta-cli.exe` for terminal automation. The CLI retains explicit network
configuration so scripts and managed environments remain in control:

```powershell
$env:PORTA_TOKEN = "replace-with-the-same-secret"
./porta-cli.exe `
  --server https://vpn.example.com:8443 `
  --transport h3 `
  --interface Porta `
  --client-id my-windows-pc
```

For a compatible private gateway using a self-signed certificate, pin the
SHA-256 thumbprint instead of disabling TLS verification. The value may contain
colons or hyphens and may start with `sha256:`:

```powershell
./porta-cli.exe `
  --server https://vpn.example.com:8443 `
  --thumbprint "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" `
  --client-id my-windows-pc
```

When used by itself, `--thumbprint` trusts only the exact leaf certificate. If
combined with `--ca`, the certificate must pass both CA and thumbprint checks.
It cannot be combined with `--insecure`.

Do not pin an automatically managed Let's Encrypt leaf certificate: its
thumbprint changes on renewal. Let the client validate those certificates
against its normal system trust store.

The CLI prints its RFC 9484 assigned address, for example `10.66.0.2/32`.
While it is still running, use another elevated PowerShell session to install
explicit routes. `ServerIp` must be the gateway's resolved public IPv4 address;
the script preserves a host route to it before adding VPN routes:

```powershell
./scripts/windows-up.ps1 `
  -AddressCidr 10.66.0.2/32 `
  -ServerIp 203.0.113.10 `
  -InterfaceAlias Porta `
  -DnsServer 1.1.1.1
```

If UDP is unavailable, change the client to `--transport h2`; it will keep
using MASQUE and carry IP packets in DATAGRAM capsules. Remove client routes
and DNS settings with:

```powershell
./scripts/windows-down.ps1 -InterfaceAlias Porta
```

CLI route changes remain explicit so operators can apply organization-specific
routing policy. The desktop UI uses the bundled elevated helper for the same
operations. Deployments requiring a kill switch should enforce it with Windows
Filtering Platform or managed firewall policy.

## Android client

Build the optimized APKs and install the one matching the device:

```sh
make android
adb shell getprop ro.product.cpu.abi
adb install -r android/app/build/outputs/apk/release/app-arm64-v8a-release.apk
```

Available outputs are `arm64-v8a` for current phones and tablets,
`armeabi-v7a` for older 32-bit ARM devices, and `x86_64` for emulators. The
release build strips Go debug symbols, shrinks Kotlin/resources, and packages
only one native runtime per APK. A local build uses the Android debug signing
key unless release-signing environment variables are configured.

Open Porta, tap **Add profile**, and enter:

- Profile name: any recognizable label, such as `Test gateway`
- Gateway: `https://htun.i-csu.org:8443`
- Token: the value after `PORTA_TOKEN=` in `/etc/porta/porta.env` on the server
- Client ID: a stable unique value such as `android-phone`

Save the profile and use its switch to connect or disconnect. Approve Android's
VPN prompt and allow notifications if prompted. The app first connects with
native HTTP/3 MASQUE over UDP 8443. The status changes to
`Connected over HTTP/3 MASQUE`. If UDP or HTTP/3 is
unavailable, it automatically falls back to the four-lane HTTP/2 transport over
TCP 8443. The fallback opens four independent TCP connections, reserves
one lane for DNS, and hashes other flows across the remaining lanes so packet
loss stalls only one subset of traffic. Authentication, certificate, and
invalid-configuration failures do not trigger a less secure fallback.

The app supports multiple named VPN server profiles. Tokens are encrypted with
a non-exportable Android Keystore key, only one profile can be connected at a
time, and the selected profile is visually highlighted. Enable
**Reconnect after device restart** on one profile when unattended boot recovery
is desired; Android must already have granted this app VPN permission. Retrieve
the initial client token on the server when needed with:

```sh
sudo sed -n 's/^PORTA_TOKEN=//p' /etc/porta/porta.env
```

The dashboard includes a 60-second real-time upload/download chart with current
rates and session totals. Tap **Log** to inspect a bounded local history of
connection attempts, transport fallback, reconnect delays, failures, and
disconnects. Tokens and authorization headers are never written to this log.

Turn off the active profile before uninstalling the app or switching to another
VPN profile.
If the network or server is temporarily unavailable, the app keeps the VPN
interface active and reconnects with a delay that grows from about one second
to a maximum of about 31 seconds. Authentication failures and invalid gateway
responses stop immediately instead of retrying forever.

With a device attached and an active Porta connection, exercise repeated Wi-Fi
loss and recovery:

```sh
./scripts/android-soak.sh 20
```

The debug build trusts system and user-installed certificate authorities to
support local testing. The release build trusts only the Android system trust
store and contains no insecure-TLS switch. The HTTP/3 path uses the Go
`quic-go` MASQUE implementation through a generated Android AAR. Android
resolves the gateway on the selected underlying network, protects the UDP
socket from the VPN, and binds it to that network before QUIC starts.

For a signed release APK, provide signing credentials through environment
variables and build the release variant:

```sh
export PORTA_ANDROID_KEYSTORE=/secure/path/porta-release.jks
export PORTA_ANDROID_KEYSTORE_PASSWORD='...'
export PORTA_ANDROID_KEY_ALIAS=porta
export PORTA_ANDROID_KEY_PASSWORD='...'
cd android
./gradlew testDebugUnitTest assembleRelease
```

Do not commit the keystore or passwords. Prefer managed Play App Signing for
public distribution and protect the upload key separately.

GitHub Actions runs Go tests, race detection, vet, cross-platform builds, and
Android builds on pushes and pull requests. Tags matching `v*` create a GitHub
release containing Linux AMD64/ARM64 servers, clients and key generators, the
Windows client, Android APKs, deployment tools, and `SHA256SUMS`. Configure
these repository Actions secrets before tagging to use production Android
signing; without them, the existing development signing fallback is used:

- `PORTA_ANDROID_KEYSTORE_BASE64`
- `PORTA_ANDROID_KEYSTORE_PASSWORD`
- `PORTA_ANDROID_KEY_ALIAS`
- `PORTA_ANDROID_KEY_PASSWORD`

## Protocol endpoints

- Admin-listener `GET /healthz` is unauthenticated and returns only
  `{"status":"ok"}`.
- Admin-listener `GET /readyz` is unauthenticated and reports that the initialized
  gateway handler is ready to accept tunnel requests.
- Admin-listener `GET /metrics` is enabled only when
  `PORTA_METRICS_TOKEN` is set and requires that exact bearer token.
- Admin-listener `GET /` serves the client-management UI. Its `/api/*`
  requests require `PORTA_ADMIN_TOKEN`.
- Ordinary public `GET` and `HEAD` requests receive the Porta landing page by
  default; operational endpoints are never routed on that listener.
- `CONNECT /.well-known/masque/ip/*/*/` implements the RFC 9484 default URI
  template for unrestricted IPv4 proxying. It requires `:protocol=connect-ip`,
  `Capsule-Protocol: ?1`, a bearer token, and a stable client ID.
- `POST /v1/tunnel` is Android's authenticated four-lane HTTP/2 fallback when
  HTTP/3 is unavailable. Requests missing valid lane metadata are rejected.
- A token identifies a client account; `X-Porta-Client-ID` identifies one
  enrolled device under that account. The account/device pair retains its
  lease and cannot collide with the same device ID in another account.

RFC 9484 does not standardize DNS or link-MTU configuration. Porta sends these
as optional `X-Porta-DNS` and `X-Porta-MTU` response extensions. The default MTU
is 1100 so complete tunneled IP packets fit conservative mobile QUIC Datagram
limits before path-MTU discovery has increased the available payload size.

Logs contain client IDs, tunnel addresses, remote IPs, and transport names, but
never intentionally contain bearer tokens or packet contents. IPv6 assignment,
configurable split routing, multi-instance HA, and kill-switch policy require
the coordinated architecture phases described in
`docs/architecture.md`.
