# hTun

hTun is a small, auditable IPv4 VPN MVP implementing MASQUE `CONNECT-IP`
(RFC 9484). The gateway accepts HTTP/2 over TCP and HTTP/3 over QUIC/UDP on the
same port. The repository includes a Linux gateway, a Windows Wintun client,
and an Android `VpnService` client.

It is designed for authorized remote access and compatibility with standard
HTTP infrastructure. A neutral landing page prevents casual browser visits
from identifying the service, but the tunnel does not impersonate browser
traffic and cannot promise to be undetectable. Read
[the threat model](docs/threat-model.md) before deployment.

## Current scope

- RFC 9484 Extended CONNECT with `:protocol=connect-ip`
- ADDRESS_REQUEST, ADDRESS_ASSIGN, and ROUTE_ADVERTISEMENT capsules
- HTTP/3 IP packets in QUIC Datagrams with Context ID 0
- HTTP/2 and HTTP/3-without-Datagram fallback using RFC 9297 DATAGRAM capsules
- Bearer authentication, per-client IPv4 `/32` leases, and source validation
- One Linux TUN interface with bounded per-client receive queues
- Durable per-client lease state across planned gateway restarts
- Client accounts with hashed tokens and configurable multi-device limits
- Authenticated Prometheus metrics
- Neutral browser cover page for ordinary public HTTP requests
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

The Android debug APK is written to
`android/app/build/outputs/apk/debug/app-debug.apk`.

## One-click production deployment

For a standalone Linux server, deploy direct HTTP/2 and HTTP/3 on TCP and UDP
443 with automatic Let's Encrypt issuance:

```sh
sudo ./scripts/deploy.sh \
  --domain vpn.example.com \
  --acme-email admin@example.com
```

Public TCP port 80 must reach hTun for the HTTP-01 challenge. If another web
server already owns ports 80 and 443, use an externally managed certificate
and choose another direct port:

```sh
sudo ./scripts/deploy.sh \
  --domain vpn.example.com \
  --cert /absolute/path/vpn.example.com.crt \
  --key /absolute/path/vpn.example.com.key \
  --port 8443
```

The command builds and installs hTun, creates credentials on first use,
configures systemd, TLS issuance or certificate synchronization, QUIC socket
buffers, forwarding, and NAT, then verifies the TLS readiness endpoint. It
preserves credentials and leases when run again for an upgrade and rolls back
the service configuration if deployment fails. It does not modify reverse
proxy configuration or cloud firewall rules.

See [the production deployment guide](docs/deployment.md) for prerequisites,
custom ports and networks, reverse-proxy fallback, firewall rules, credentials,
validation, Android setup, and removal.

## Gateway

Use separate random bootstrap, admin, and metrics tokens. The bootstrap token
creates the first client account only when the registry does not yet exist.
Pass tokens through the environment so they do not appear in the process list.
The server obtains and renews its certificate through Let's Encrypt. Point the
domain's A/AAAA record at the gateway, expose TCP port 80 for the HTTP-01
challenge, and expose TCP and UDP port 443:

```sh
export HTUN_TOKEN="replace-with-a-random-32-byte-or-longer-secret"
export HTUN_ADMIN_TOKEN="use-a-different-random-admin-secret"
export HTUN_METRICS_TOKEN="use-a-different-random-secret"
sudo --preserve-env=HTUN_TOKEN,HTUN_ADMIN_TOKEN,HTUN_METRICS_TOKEN ./bin/htun-server \
  --listen :443 \
  --admin-listen 127.0.0.1:9090 \
  --acme-domain vpn.example.com \
  --acme-email admin@example.com \
  --acme-cache /var/lib/htun/acme \
  --acme-http-listen :80 \
  --client-registry /var/lib/htun/clients.json \
  --interface htun0 \
  --pool 10.66.0.0/24 \
  --dns 1.1.1.1 \
  --mtu 1100
```

The loopback admin UI manages client accounts, tokens, device limits, enabled
state, and enrolled devices without restarting hTun. Tokens are generated with
32 random bytes, stored only as SHA-256 hashes, and displayed once when created
or rotated. One client token may be used by several device IDs up to that
client's configured limit.

The daemon creates `htun0`, but deliberately does not modify forwarding or
firewall state. In another root shell, after reviewing the script, configure
the interface and NAT. Replace `eth0` with the real egress interface:

```sh
sudo ./scripts/server-up.sh htun0 10.66.0.1/24 10.66.0.0/24 eth0
```

Open both TCP and UDP port 443 at the host and cloud firewalls. Tear down only
the nftables table owned by this project with:

```sh
sudo ./scripts/server-down.sh htun0 eth0
```

When Docker's `DOCKER-USER` chain is present, the setup script also installs
the two forwarding exceptions required for `htun0`. Passing the external
interface to the teardown script removes those exceptions.

The current Go HTTP/2 implementation gates Extended CONNECT behind the
official `GODEBUG=http2xconnect=1` compatibility switch. `htun-server` detects
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

Ordinary browser requests receive a neutral HTML landing page by default.
`/healthz`, `/readyz`, `/metrics`, and the admin UI are not exposed on the
public tunnel listener. They are available only from the loopback listener at
`127.0.0.1:9090` by default. Reach the UI through an SSH tunnel and open
`http://127.0.0.1:9090`; API data requires `HTUN_ADMIN_TOKEN`. Use
`--cover-site=false` only when an API-style 404 is preferred over the landing
page. This is camouflage for casual visitors, not a security boundary.

### Direct HTTP/3 alongside an existing web server

When another web server already owns port 443, run hTun directly on another
public port, such as 8443. The existing service can continue managing the
domain certificate and serving web traffic on 443, while tunnel traffic
connects directly to hTun over TCP and UDP 8443:

```sh
sudo ./bin/htun-server \
  --listen :8443 \
  --tls-cert /etc/htun/tls/server.crt \
  --tls-key /etc/htun/tls/server.key \
  --client-registry /var/lib/htun/clients.json \
  --interface htun0 \
  --pool 10.66.0.0/24 \
  --dns 1.1.1.1 \
  --mtu 1100
```

Open both TCP and UDP 8443 in the host and cloud firewalls. HTTP/2 uses the
TCP listener and HTTP/3/MASQUE uses the UDP listener. For good QUIC throughput,
install the included socket-buffer limits:

```sh
sudo install -m 0644 deploy/99-htun-quic.conf /etc/sysctl.d/99-htun-quic.conf
sudo sysctl --system
```

The static TLS loader detects atomically replaced certificate files during
new TLS handshakes, so the gateway does not need a restart solely to load a
renewed certificate. If another service owns certificate renewal, do not grant
the hardened hTun process access to its private storage. Instead, use the
included root-run certificate synchronization timer:

```sh
sudo install -d -m 0755 /usr/local/libexec/htun
sudo install -m 0755 scripts/sync-cert.sh /usr/local/libexec/htun/
sudo install -m 0644 deploy/htun-cert-sync.service deploy/htun-cert-sync.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl start htun-cert-sync.service
sudo systemctl enable --now htun-cert-sync.timer
```

Adjust the source certificate and key paths in `htun-cert-sync.service` for
the domain before installing it. The synchronization script validates that the
certificate and private key match and replaces both destination files. hTun
loads the renewed pair on subsequent TLS handshakes without disconnecting
active tunnels.

An existing reverse proxy may retain a compatibility endpoint on 443 by
forwarding HTTP/2 requests to hTun's TLS listener with response buffering
disabled and TLS server name `vpn.example.com`. This carries only the HTTP/2
fallback; native HTTP/3/MASQUE clients connect directly to UDP 8443.

Check the direct TLS listener locally without disabling certificate
verification:

```sh
curl http://127.0.0.1:9090/readyz
curl --resolve vpn.example.com:8443:127.0.0.1 \
  -H "Authorization: Bearer $HTUN_METRICS_TOKEN" \
  http://127.0.0.1:9090/metrics
```

### Behind a reverse proxy

Use `--behind-proxy` when a reverse proxy terminates TLS and manages the public
certificate. hTun then serves plaintext HTTP/2 (h2c) on its
TCP listener and does not start ACME, TLS, or HTTP/3 listeners. Bind the
backend to loopback so it cannot be reached directly:

```sh
export HTUN_TOKEN="replace-with-a-random-32-byte-or-longer-secret"
export HTUN_ADMIN_TOKEN="use-a-different-random-admin-secret"
sudo --preserve-env=HTUN_TOKEN,HTUN_ADMIN_TOKEN ./bin/htun-server \
  --behind-proxy \
  --listen 127.0.0.1:8443 \
  --admin-listen 127.0.0.1:9090 \
  --client-registry /var/lib/htun/clients.json \
  --interface htun0 \
  --pool 10.66.0.0/24 \
  --dns 1.1.1.1 \
  --mtu 1100
```

Configure the reverse proxy to use HTTP/2 cleartext for the loopback backend,
disable response buffering, and keep `/metrics` inaccessible publicly.

The repository includes `deploy/htun.service` for a persistent direct TLS
deployment on TCP and UDP 8443 using `eth0` as the external interface. Adjust
the domain-specific certificate synchronization unit and network values before
installing:

```sh
make build
sudo install -m 0755 bin/htun-server /usr/local/bin/htun-server
sudo install -d -m 0755 /usr/local/libexec/htun /etc/htun
sudo install -m 0755 scripts/server-up.sh scripts/server-down.sh scripts/sync-cert.sh /usr/local/libexec/htun/
{
  printf 'HTUN_TOKEN=%s\n' "$(openssl rand -hex 32)"
  printf 'HTUN_ADMIN_TOKEN=%s\n' "$(openssl rand -hex 32)"
  printf 'HTUN_METRICS_TOKEN=%s\n' "$(openssl rand -hex 32)"
} | sudo tee /etc/htun/htun.env >/dev/null
sudo chmod 0600 /etc/htun/htun.env
sudo install -m 0644 deploy/htun.service deploy/htun-cert-sync.service deploy/htun-cert-sync.timer /etc/systemd/system/
sudo install -m 0644 deploy/99-htun-quic.conf /etc/sysctl.d/99-htun-quic.conf
sudo sysctl --system
sudo systemctl daemon-reload
sudo systemctl start htun-cert-sync.service
sudo systemctl enable --now htun
sudo systemctl enable --now htun-cert-sync.timer
```

Validate the direct listener after deployment:

```sh
curl http://127.0.0.1:9090/healthz
```

Operational checks:

```sh
systemctl status htun
journalctl -u htun -f
curl http://127.0.0.1:9090/readyz
ADMIN_TOKEN="$(sudo sed -n 's/^HTUN_ADMIN_TOKEN=//p' /etc/htun/htun.env)"
curl -H "Authorization: Bearer $ADMIN_TOKEN" http://127.0.0.1:9090/api/clients
METRICS_TOKEN="$(sudo sed -n 's/^HTUN_METRICS_TOKEN=//p' /etc/htun/htun.env)"
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
sudo install -m 0755 bin/htun-server /usr/local/bin/htun-server
sudo systemctl restart htun
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

Run hTun directly when HTTP/3 or standards-based MASQUE transport is required.

## Windows client

Download the signed `wintun.dll` for the target architecture from the official
[Wintun site](https://www.wintun.net/) and place it next to the client
executable. Run the client in an elevated PowerShell session:

```powershell
$env:HTUN_TOKEN = "replace-with-the-same-secret"
./htun-client-windows-amd64.exe `
  --server https://vpn.example.com:8443 `
  --transport h3 `
  --interface hTun `
  --client-id my-windows-pc
```

For a compatible private gateway using a self-signed certificate, pin the
SHA-256 thumbprint instead of disabling TLS verification. The value may contain
colons or hyphens and may start with `sha256:`:

```powershell
./htun-client-windows-amd64.exe `
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

The client prints its RFC 9484 assigned address, for example `10.66.0.2/32`.
While it is still running, use another elevated PowerShell session to install
explicit routes. `ServerIp` must be the gateway's resolved public IPv4 address;
the script preserves a host route to it before adding VPN routes:

```powershell
./scripts/windows-up.ps1 `
  -AddressCidr 10.66.0.2/32 `
  -ServerIp 203.0.113.10 `
  -InterfaceAlias hTun `
  -DnsServer 1.1.1.1
```

If UDP is unavailable, change the client to `--transport h2`; it will keep
using MASQUE and carry IP packets in DATAGRAM capsules. Remove client routes
and DNS settings with:

```powershell
./scripts/windows-down.ps1 -InterfaceAlias hTun
```

The MVP keeps route changes explicit. It does not install a kill switch;
deployments that require one should enforce it with Windows Filtering Platform
or managed firewall policy.

## Android client

Build and install the debug APK:

```sh
make android
adb install -r android/app/build/outputs/apk/debug/app-debug.apk
```

Open hTun, tap **Add profile**, and enter:

- Profile name: any recognizable label, such as `Test gateway`
- Gateway: `https://htun.i-csu.org:8443`
- Token: the value after `HTUN_TOKEN=` in `/etc/htun/htun.env` on the server
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
sudo sed -n 's/^HTUN_TOKEN=//p' /etc/htun/htun.env
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

With a device attached and an active hTun connection, exercise repeated Wi-Fi
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
export HTUN_ANDROID_KEYSTORE=/secure/path/htun-release.jks
export HTUN_ANDROID_KEYSTORE_PASSWORD='...'
export HTUN_ANDROID_KEY_ALIAS=htun
export HTUN_ANDROID_KEY_PASSWORD='...'
cd android
./gradlew testDebugUnitTest assembleRelease
```

Do not commit the keystore or passwords. Prefer managed Play App Signing for
public distribution and protect the upload key separately.

GitHub Actions runs Go tests, race detection, vet, cross-platform builds, and
Android builds on pushes and pull requests. Tags matching `v*` create a GitHub
release. Configure these repository Actions secrets before tagging:

- `HTUN_ANDROID_KEYSTORE_BASE64`
- `HTUN_ANDROID_KEYSTORE_PASSWORD`
- `HTUN_ANDROID_KEY_ALIAS`
- `HTUN_ANDROID_KEY_PASSWORD`

## Protocol endpoints

- Admin-listener `GET /healthz` is unauthenticated and returns only
  `{"status":"ok"}`.
- Admin-listener `GET /readyz` is unauthenticated and reports that the initialized
  gateway handler is ready to accept tunnel requests.
- Admin-listener `GET /metrics` is enabled only when
  `HTUN_METRICS_TOKEN` is set and requires that exact bearer token.
- Admin-listener `GET /` serves the client-management UI. Its `/api/*`
  requests require `HTUN_ADMIN_TOKEN`.
- Ordinary public `GET` and `HEAD` requests receive only the neutral HTML cover
  page by default; operational endpoints are never routed on that listener.
- `CONNECT /.well-known/masque/ip/*/*/` implements the RFC 9484 default URI
  template for unrestricted IPv4 proxying. It requires `:protocol=connect-ip`,
  `Capsule-Protocol: ?1`, a bearer token, and a stable client ID.
- `POST /v1/tunnel` is Android's authenticated four-lane HTTP/2 fallback when
  HTTP/3 is unavailable. Requests missing valid lane metadata are rejected.
- A token identifies a client account; `X-HTun-Client-ID` identifies one
  enrolled device under that account. The account/device pair retains its
  lease and cannot collide with the same device ID in another account.

RFC 9484 does not standardize DNS or link-MTU configuration. hTun sends these
as optional `X-HTun-DNS` and `X-HTun-MTU` response extensions. The default MTU
is 1100 so complete tunneled IP packets fit conservative mobile QUIC Datagram
limits before path-MTU discovery has increased the available payload size.

Logs contain client IDs, tunnel addresses, remote IPs, and transport names, but
never intentionally contain bearer tokens or packet contents. IPv6 assignment,
configurable split routing, multi-instance HA, and kill-switch policy require
the coordinated architecture phases described in
`docs/architecture.md`.
