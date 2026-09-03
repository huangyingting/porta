# hTun

hTun is a small, auditable IPv4 VPN MVP implementing MASQUE `CONNECT-IP`
(RFC 9484). The gateway accepts HTTP/2 over TCP and HTTP/3 over QUIC/UDP on the
same port. The repository includes a Linux gateway, a Windows Wintun client,
and an Android `VpnService` client.

It is designed for authorized remote access and compatibility with standard
HTTP infrastructure. It does not impersonate browser traffic and cannot
promise to be undetectable. Read [the threat model](docs/threat-model.md)
before deployment.

## Current scope

- RFC 9484 Extended CONNECT with `:protocol=connect-ip`
- ADDRESS_REQUEST, ADDRESS_ASSIGN, and ROUTE_ADVERTISEMENT capsules
- HTTP/3 IP packets in QUIC Datagrams with Context ID 0
- HTTP/2 and HTTP/3-without-Datagram fallback using RFC 9297 DATAGRAM capsules
- Bearer authentication, per-client IPv4 `/32` leases, and source validation
- One Linux TUN interface with bounded per-client receive queues
- Durable per-client lease state across planned gateway restarts
- Per-device credentials with an optional migration fallback token
- Authenticated Prometheus metrics
- Windows Wintun client plus explicit route setup/teardown scripts
- Android HTTP/2 `VpnService` client using protected sockets
- Backward-compatible private stream protocol for Android and older clients
- Real bidirectional HTTP/2 Extended CONNECT and HTTP/3 Datagram tests

Desktop clients use MASQUE by default. The older `POST /v1/tunnel` protocol is
retained behind `--protocol legacy` because OkHttp does not expose the HTTP/2
Extended CONNECT pseudo-header required by `CONNECT-IP`. Details are in
[the architecture document](docs/architecture.md).

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

Public TCP port 80 must reach hTun for the HTTP-01 challenge. If Caddy or
another service already owns ports 80 and 443, use its existing certificate
and choose another direct port:

```sh
sudo ./scripts/deploy.sh \
  --domain vpn.example.com \
  --cert /absolute/path/vpn.example.com.crt \
  --key /absolute/path/vpn.example.com.key \
  --port 8443
```

The command builds and installs hTun, creates credentials on first use,
configures systemd, certificate synchronization, QUIC socket buffers,
forwarding, and NAT, then verifies the TLS readiness endpoint. It preserves
credentials and leases when run again for an upgrade. It does not modify the
shared Caddyfile or cloud firewall.

See [the production deployment guide](docs/deployment.md) for prerequisites,
custom ports and networks, Caddy fallback, firewall rules, credentials,
validation, Android setup, and removal.

## Gateway

Use a random token of at least 32 bytes. Pass it through the environment so it
does not appear in the process list. The server obtains and renews its
certificate through Let's Encrypt. Point the domain's A/AAAA record at the
gateway, expose TCP port 80 for the HTTP-01 challenge, and expose TCP and UDP
port 443:

```sh
export HTUN_TOKEN="replace-with-a-random-32-byte-or-longer-secret"
export HTUN_METRICS_TOKEN="use-a-different-random-secret"
sudo --preserve-env=HTUN_TOKEN ./bin/htun-server \
  --listen :443 \
  --acme-domain vpn.example.com \
  --acme-email admin@example.com \
  --acme-cache /var/lib/htun/acme \
  --acme-http-listen :80 \
  --interface htun0 \
  --pool 10.66.0.0/24 \
  --dns 1.1.1.1 \
  --mtu 1100
```

For per-device revocation, create a root-readable credential file containing
one stable client ID and token per line:

```text
android-phone=replace-with-a-random-device-secret
windows-laptop=replace-with-another-random-device-secret
```

Start the server with `--client-token-file /etc/htun/clients`. A listed client
must use its own token; the global `HTUN_TOKEN` remains a fallback only for
unlisted clients during migration. Remove `HTUN_TOKEN` after every active
client has an entry to enforce device-only authentication. Rotate or revoke a
credential by replacing or removing its line and restarting hTun.

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

### Direct HTTP/3 alongside Caddy

When Caddy already owns port 443, run hTun directly on another public port,
such as 8443. Caddy can continue managing the domain certificate and serving
web traffic on 443, while tunnel traffic connects directly to hTun over TCP
and UDP 8443:

```sh
sudo ./bin/htun-server \
  --listen :8443 \
  --tls-cert /etc/htun/tls/server.crt \
  --tls-key /etc/htun/tls/server.key \
  --client-token-file /etc/htun/clients \
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
renewed certificate. If Caddy owns certificate renewal, do not grant the
hardened hTun process access to Caddy's private storage. Instead, use the
included root-run certificate synchronization timer:

```sh
sudo install -d -m 0755 /usr/local/libexec/htun
sudo install -m 0755 scripts/sync-caddy-cert.sh /usr/local/libexec/htun/
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

Caddy may retain a compatibility endpoint on 443 by proxying to hTun's TLS
listener. This carries only the HTTP/2 fallback; native HTTP/3/MASQUE clients
connect directly to UDP 8443:

```caddyfile
vpn.example.com {
  @metrics path /metrics
  respond @metrics 404

  reverse_proxy https://127.0.0.1:8443 {
    flush_interval -1
    transport http {
      tls_server_name vpn.example.com
    }
  }
}
```

Check the direct TLS listener locally without disabling certificate
verification:

```sh
curl --resolve vpn.example.com:8443:127.0.0.1 https://vpn.example.com:8443/readyz
curl --resolve vpn.example.com:8443:127.0.0.1 \
  -H "Authorization: Bearer $HTUN_METRICS_TOKEN" \
  https://vpn.example.com:8443/metrics
```

### Behind a reverse proxy

Use `--behind-proxy` when a reverse proxy such as Caddy terminates TLS and
manages the public certificate. hTun then serves plaintext HTTP/2 (h2c) on its
TCP listener and does not start ACME, TLS, or HTTP/3 listeners. Bind the
backend to loopback so it cannot be reached directly:

```sh
export HTUN_TOKEN="replace-with-a-random-32-byte-or-longer-secret"
sudo --preserve-env=HTUN_TOKEN ./bin/htun-server \
  --behind-proxy \
  --listen 127.0.0.1:8443 \
  --interface htun0 \
  --pool 10.66.0.0/24 \
  --dns 1.1.1.1 \
  --mtu 1100
```

Proxy the domain to that h2c backend and disable response buffering:

```caddyfile
vpn.example.com {
  header Strict-Transport-Security "max-age=31536000"
  log

  @metrics path /metrics
  respond @metrics 404

  reverse_proxy h2c://127.0.0.1:8443 {
    flush_interval -1
  }
}
```

The repository includes `deploy/htun.service` for a persistent direct TLS
deployment on TCP and UDP 8443 using `eth0` as the external interface. Adjust
the domain-specific certificate synchronization unit and network values before
installing:

```sh
make build
sudo install -m 0755 bin/htun-server /usr/local/bin/htun-server
sudo install -d -m 0755 /usr/local/libexec/htun /etc/htun
sudo install -m 0755 scripts/server-up.sh scripts/server-down.sh scripts/sync-caddy-cert.sh /usr/local/libexec/htun/
{
  printf 'HTUN_TOKEN=%s\n' "$(openssl rand -hex 32)"
  printf 'HTUN_METRICS_TOKEN=%s\n' "$(openssl rand -hex 32)"
} | sudo tee /etc/htun/htun.env >/dev/null
sudo install -m 0600 /dev/null /etc/htun/clients
sudo chmod 0600 /etc/htun/htun.env
sudo install -m 0644 deploy/htun.service deploy/htun-cert-sync.service deploy/htun-cert-sync.timer /etc/systemd/system/
sudo install -m 0644 deploy/99-htun-quic.conf /etc/sysctl.d/99-htun-quic.conf
sudo sysctl --system
sudo systemctl daemon-reload
sudo systemctl start htun-cert-sync.service
sudo systemctl enable --now htun
sudo systemctl enable --now htun-cert-sync.timer
```

Validate and reload Caddy after adding the site block:

```sh
sudo caddy validate --config /etc/caddy/Caddyfile
sudo systemctl reload caddy
curl https://vpn.example.com/healthz
```

Operational checks:

```sh
systemctl status htun
journalctl -u htun -f
curl https://vpn.example.com/readyz
METRICS_TOKEN="$(sudo sed -n 's/^HTUN_METRICS_TOKEN=//p' /etc/htun/htun.env)"
# This loopback HTTP check applies only to the --behind-proxy h2c deployment.
curl -H "Authorization: Bearer $METRICS_TOKEN" http://127.0.0.1:8443/metrics
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
QUIC datagrams to the backend. Clients behind Caddy must therefore use the
HTTP/2 compatibility stream:

```sh
HTUN_TOKEN="replace-with-the-same-secret" ./bin/htun-client \
  --server https://vpn.example.com \
  --transport h2 \
  --protocol legacy \
  --client-id my-client
```

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
  --protocol masque `
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
using MASQUE and carry IP packets in DATAGRAM capsules. `--protocol legacy` is
only a compatibility option. Remove client routes and DNS settings with:

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

For the deployed test gateway, enter:

- Gateway: `https://htun.i-csu.org:8443`
- Token: the value after `HTUN_TOKEN=` in `/etc/htun/htun.env` on the server
- Client ID: a stable unique value such as `android-phone`

Tap **Connect**, approve Android's VPN prompt, and allow notifications if
prompted. The app first connects with native HTTP/3 MASQUE over UDP 8443. The
status changes to `Connected over HTTP/3 MASQUE`. If UDP or HTTP/3 is
unavailable, it automatically falls back to the HTTP/2 compatibility transport
over TCP 8443. Authentication, certificate, and invalid-configuration failures
do not trigger a less secure fallback.

By default, the token is passed directly to the private service and cleared
from the UI without persistence. Enable **Remember token securely** to encrypt
it with a non-exportable Android Keystore key.
Enable **Reconnect after device restart** only when unattended boot recovery
is desired; Android must already have granted this app VPN permission.
Disabling secure storage removes the encrypted token and disables boot
reconnect. Retrieve the fallback token on the server when needed with:

```sh
sudo sed -n 's/^HTUN_TOKEN=//p' /etc/htun/htun.env
```

Tap **Disconnect** before uninstalling the app or switching to another VPN.
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

- `GET /healthz` is unauthenticated and returns only `{"status":"ok"}`.
- `GET /readyz` is unauthenticated and reports that the initialized gateway
  handler is ready to accept tunnel requests.
- `GET /metrics` is enabled only when `HTUN_METRICS_TOKEN` is set and requires
  that separate bearer token. Keep it blocked at the public reverse proxy and
  scrape the loopback h2c backend.
- `CONNECT /.well-known/masque/ip/*/*/` implements the RFC 9484 default URI
  template for unrestricted IPv4 proxying. It requires `:protocol=connect-ip`,
  `Capsule-Protocol: ?1`, a bearer token, and a stable client ID.
- `POST /v1/tunnel` is the authenticated private compatibility protocol used
  by the current Android client.
- A reconnect using the same client ID reuses its retained lease and replaces
  the older stream. When the pool is full, the oldest inactive lease is
  reclaimed for a new client.

RFC 9484 does not standardize DNS or link-MTU configuration. hTun sends these
as optional `X-HTun-DNS` and `X-HTun-MTU` response extensions. The default MTU
is 1100 so complete tunneled IP packets fit conservative mobile QUIC Datagram
limits before path-MTU discovery has increased the available payload size.

Logs contain client IDs, tunnel addresses, remote IPs, and transport names, but
never intentionally contain bearer tokens or packet contents. IPv6 assignment,
configurable split routing, multi-instance HA, and kill-switch policy require
the coordinated architecture phases described in
`docs/architecture.md`.
