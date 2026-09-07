# Production deployment

This guide deploys Porta directly on one TCP and UDP port. An existing web
server may continue serving websites and renewing the certificate on port 443,
but native HTTP/3/MASQUE traffic goes directly to Porta and does not pass
through a reverse proxy.

## Choose a deployment mode

| Environment | Command options | Tunnel port | Certificate renewal |
|---|---|---:|---|
| Standalone server | `--domain vpn.example.com` | 443 by default | Porta/Let's Encrypt |
| Another service uses 80/443 | `--domain`, `--cert`, `--key`, `--port 8443` | 8443 | External issuer |
| Custom standalone port | `--domain`, `--port PORT` | Configured value | Porta/Let's Encrypt through TCP 80 |

`--port` controls both the TCP HTTP/2 listener and UDP HTTP/3/QUIC listener.
It defaults to 443. The Android gateway URL must include the port when it is
not 443.

## Prerequisites

- Linux with `curl`, `sha256sum`, `flock` (util-linux), systemd, nftables,
  `/dev/net/tun`, and IPv4 forwarding support
- A DNS hostname pointing to the server
- Either public TCP port 80 for automatic Let's Encrypt issuance, or an
  existing certificate and private key covering the hostname
- Both TCP and UDP on the selected port allowed by host and cloud firewalls

## Download the deployment bundle

Each tagged GitHub release contains a deployment bundle plus standalone server
and client binaries. Download and verify the latest bundle:

```sh
gh release download --repo huangyingting/porta \
  --pattern porta-deploy.tar.gz --pattern SHA256SUMS
grep ' porta-deploy.tar.gz$' SHA256SUMS | sha256sum -c -
tar -xzf porta-deploy.tar.gz
cd porta
export GH_TOKEN=$(gh auth token)
```

The repository is private, so `gh` must be authenticated with an account that
can read it. Preserve `GH_TOKEN` through `sudo` when using release deployment;
the token is not written to Porta's configuration.

By default, `scripts/deploy.sh` downloads the matching Linux AMD64 or ARM64
`porta-server` from that release and verifies it with `SHA256SUMS`. Pass
`--release vX.Y.Z` to pin a release that includes the client download portal.
Developers working from a full source checkout can pass `--build-local`
instead. Local builds require Go plus a stable Rust toolchain with Cargo; the
deployed server binary is built from `rust/porta-server`.

## One-command installation with Let's Encrypt

When no certificate paths are supplied, Porta obtains and renews its own
Let's Encrypt certificate:

```sh
sudo --preserve-env=GH_TOKEN ./scripts/deploy.sh \
  --domain vpn.example.com \
  --acme-email admin@example.com
```

The email is optional. Let's Encrypt HTTP-01 validation always connects to
public TCP port 80, regardless of the configured tunnel port. DNS must already
point to the server, the cloud and host firewalls must allow TCP 80, and no
other process may own port 80.

This mode is appropriate for a standalone gateway. If another service already
owns port 80, use the existing-certificate mode below instead; stopping a
production web server merely to renew a second certificate is not recommended.

## One-command installation with an existing certificate

From the extracted deployment bundle or a checked-out Porta repository:

```sh
sudo --preserve-env=GH_TOKEN ./scripts/deploy.sh \
  --domain vpn.example.com \
  --cert /etc/letsencrypt/live/vpn.example.com/fullchain.pem \
  --key /etc/letsencrypt/live/vpn.example.com/privkey.pem \
  --port 8443
```

Certificate and key paths and their resolved targets are validated before
installation. Neither may reside under `/tmp` or `/var/tmp`, because the
hardened synchronization unit uses a private temporary directory. The supplied
live symlink paths are preserved so later synchronization follows certificate
renewal. Private-CA and self-managed certificates are supported: deployment
verifies the key pair before installation, then uses the installed certificate
as explicit trust material to verify TLS and the hostname on the loopback-bound
public listener. These local probes bypass HTTP proxy environment settings.

Porta's authenticated HTTPS CONNECT proxy is enabled on the same TLS port by
default. Add `--disable-forward-proxy` only when the deployment should provide
VPN service without the proxy.

The default deployment:

- listens on TCP and UDP 443;
- uses HTTP/3 MASQUE with HTTP/2 fallback;
- enables authenticated HTTPS CONNECT proxying;
- creates `porta0` and the `10.66.0.0/24` client network;
- advertises `1.1.1.1` and selects HTTP/3 MTU automatically between 1100 and
  the default 1400 ceiling; custom advertised DNS must be a
  numeric unicast IPv4 address, not loopback or link-local;
- installs narrowly scoped nftables NAT, forwarding, and public-input guard
  rules;
- installs hardened systemd services;
- either renews its own Let's Encrypt certificate or synchronizes externally
  managed certificate files every six hours;
- tunes Linux UDP buffers for QUIC;
- creates random fallback and metrics tokens on first installation;
- preserves existing credentials and lease state during upgrades.

Run `sudo ./scripts/deploy.sh --help` for network and port overrides. For
example:

```sh
sudo ./scripts/deploy.sh \
  --domain vpn.example.com \
  --cert /etc/letsencrypt/live/vpn.example.com/fullchain.pem \
  --key /etc/letsencrypt/live/vpn.example.com/privkey.pem \
  --port 8443 \
  --external-interface ens3 \
  --pool 10.77.0.0/24 \
  --gateway-cidr 10.77.0.1/24
```

### Automatic tunnel MTU

Conservative per-connection HTTP/3 selection is enabled by default, with a
1400 ceiling and 1100 discovery baseline. `--mtu` sets the gateway TUN MTU
and automatic upper bound. Use `--auto-mtu=false --mtu 1100` to disable
discovery and use a fixed 1100 MTU; another fixed MTU can be specified with
the same override. The daemon accepts the same options when started directly.
The deployment script accepts MTUs from 576 through 1400.

Automatic MTU also requires Linux to accept gateway-sourced ICMP injected
through TUN. Deployment passes the chosen `--auto-mtu=true` or
`--auto-mtu=false` mode to both the daemon and
`server-up.sh`; the helper sets `accept_local=1` and loose `rp_filter=2` only
on the owned TUN. It does not change global or physical-interface reverse-path
filtering. These interface-local settings disappear with the TUN. The helper
records the host's previous `net.ipv4.ip_forward` value under `/run/porta` and
restores it during normal cleanup when no administrator or other service has
changed the setting in the meantime.

The network helper also defaults to automatic mode:

```sh
sudo ./scripts/server-up.sh porta0 10.66.0.1/24 10.66.0.0/24 eth0 443
```

Use the actual interface/address/pool values. When selecting fixed mode in a
manually edited service unit, pass `--auto-mtu=false` to both the daemon and
network helper. Upgrade the daemon and helper together.
The required `mtu_feedback` readiness component detects missing local-source
acceptance or effective strict reverse-path filtering instead of reporting
automatic MTU ready with unusable DF feedback.

Clients need no additional setting. They increase above 1100 only after
bidirectional datagram confirmation, agree with the server before configuring
the interface, and keep that MTU until reconnect. Inconclusive discovery keeps
the conservative value; HTTP/2 and capsule-only HTTP/3 retain the configured
MTU. QUIC size reductions still trigger per-packet capsule fallback instead of
live interface resizing. See [MTU selection](architecture.md#stable-per-connection-mtu-selection)
for protocol details and oversized IPv4 handling.

### Upgrade behavior

The script serializes deployments with a lock and is idempotent. Re-running it
downloads and upgrades the server while preserving `/etc/porta/porta.env`,
`/var/lib/porta/clients.json`, and persistent leases.
The gateway address is derived from the pool unless explicitly supplied. A
pool change is rejected when existing leases are incompatible; use
`--reset-leases` to archive those leases deliberately.

The generated unit carries an inert ordering rule for `docker.service`. If
Docker is installed, deployment also adds it as a weak startup dependency so
Porta starts only after Docker has initialized its firewall chains. Porta then
installs its two forwarding exceptions in `DOCKER-USER`. Without Docker, no
Docker service is started and no iptables rules are added; Porta uses only its
isolated nftables table. If Docker is installed later, restart Porta once after
Docker starts, or rerun deployment, to add the live exceptions; subsequent
boots retain the correct ordering.

## Token portal and client downloads

Release clients are mirrored from the private GitHub release to the deployed
Porta server:

```text
porta-client-linux-amd64
porta-client-linux-arm64
porta-client-windows-amd64.zip
porta-android-arm64-v8a.apk
porta-android-armeabi-v7a.apk
porta-android-x86_64.apk
```

The neutral landing page accepts either an administrator token or a client
token. Client tokens open the protected downloads page. For scripted downloads,
create a session cookie before requesting a fixed artifact path:

```sh
curl -fsS -c porta.cookies \
  --data-urlencode "token=$PORTA_TOKEN" \
  https://vpn.example.com:8443/access >/dev/null
curl -fsSLO -b porta.cookies \
  https://vpn.example.com:8443/download/porta-android-arm64-v8a.apk
curl -fsSLO -b porta.cookies \
  https://vpn.example.com:8443/download/SHA256SUMS
grep ' porta-android-arm64-v8a.apk$' SHA256SUMS | sha256sum -c -
```

Only the listed release filenames are served. There is no directory listing,
and unauthenticated requests retain the neutral landing behavior.
Authenticated GitHub release downloads remain available as an operator
fallback.

The public listener serves a restrictive `/robots.txt` and sends
`X-Robots-Tag: noindex, nofollow, noarchive, nosnippet, noimageindex` on
landing and HTML portal responses. These directives discourage compliant
search engines and archival crawlers, but they are not access control and
cannot prevent a scraper that chooses to ignore them. Tunnel and forward-proxy
handshakes are unchanged.

## Forward proxy

The forward proxy uses the same client accounts managed by the admin UI. The
Basic-auth username is ignored and the password is the client token:

```sh
curl --proxy https://vpn.example.com:8443 \
  --proxy-basic --proxy-user 'laptop:CLIENT_TOKEN' \
  https://example.com/
```

Porta supports HTTPS `CONNECT` over HTTP/1.1 and HTTP/2. HTTP/3 is reserved for
the native MASQUE CONNECT-IP tunnel and rejects ordinary forward-proxy
CONNECT requests. Ordinary HTTP proxy requests are rejected, and only public
destinations on port 443 are permitted.
DNS results are checked before dialing, and any private, loopback, link-local,
metadata, multicast, documentation, or benchmark address rejects the request.
Only complete, validated public address sets enter the bounded 30-second DNS
cache. IPv4 and IPv6 connection attempts are interleaved with a short stagger
under one setup timeout, so an unreachable preferred family does not serialize
the full connection delay.
Proxy credentials and client-supplied forwarding identity headers are never
sent to the destination.

Valid Basic credentials activate the proxy. Porta returns a standard `407`
challenge only for CONNECT requests so browser extensions can supply stored
credentials. Ordinary unauthenticated requests still fall through to the
landing or unsupported-request behavior.
Configure ZeroOmega with type **HTTPS**, enter the Porta hostname and port, put
any value in its required username field, and use the client token as the
password. ZeroOmega supplies the stored credentials after the CONNECT-only
authentication challenge. All proxy clients for one account are represented by
one `forward-proxy` enrollment and combined usage record; they cannot be managed
individually. Porta
does not serve a public PAC file and does not cache proxy responses. Response
stream writes are flushed after 128 KiB or two milliseconds, whichever comes
first, preserving interactive latency without forcing a protocol flush for
every relay-buffer write.

The installer validates port availability before stopping an existing
gateway. If the new service cannot obtain its certificate or pass the
readiness check, it restores the previous binary, helpers, configuration and
TLS files, downloads, leases, client registry, usage state, sysctl values, and
service enablement/activity. Snapshots are taken after the old gateway and
certificate synchronization have stopped. If a rollback step fails, the script
reports the error and retains its recovery directory rather than deleting the
backups.

## Landing page and role-based portal

Porta randomly selects one of its six bundled, responsive landing templates for
each ordinary browser request. Operators can replace that pool with custom
full-page HTML files by placing one or more regular `.html` files in
`/etc/porta/landing` and restarting the service:

```sh
sudo install -m 0644 my-landing-page.html /etc/porta/landing/
sudo systemctl restart porta
```

Files are loaded in filename order at startup, and one is selected randomly
for each response. An empty directory keeps the bundled templates. Each file
is limited to 1 MiB. The landing response policy permits inline CSS and
same-origin fonts and images, but blocks scripts, external resources, framing,
and form submissions to other origins. Porta also sends `Cache-Control:
no-store` and the crawler directives described above for every template.
Direct runs can use `--landing-template-dir /absolute/path`.

Each bundled page routes its access action to the same role-based portal.
Administrator tokens open the admin console and active client tokens open the
download page. The resulting
role-scoped session expires after eight hours and uses a `Secure`, `HttpOnly`,
`SameSite=Strict` cookie. Tokens are not placed in URLs or browser storage.

```sh
sudo sed -n 's/^PORTA_ADMIN_TOKEN=//p' /etc/porta/porta.env
```

Browse to the public Porta URL and enter that token. The compact
operations table shows live sessions, persisted traffic and connection totals,
transport/address details, recent activity, capacity pressure, and stale or
unused clients. It can create, edit, disable, and delete clients; rotate tokens;
set device limits; and forget enrolled devices to free a slot. Usage is
checkpointed every 30 seconds to `/var/lib/porta/usage.json` by release
deployments. A device that still has the shared
client token can enroll again. Tokens are shown only when created or rotated.

Public admin API calls require the administrator session. Loopback admin API
calls continue to accept `Authorization: Bearer <PORTA_ADMIN_TOKEN>`.
`/healthz`, `/readyz`, and `/metrics` remain loopback-only.

For direct manual server runs, pass `--landing-page=false` to replace the landing
page with normal API 404 responses. Use `--admin-listen` to change or disable
the loopback health, readiness, metrics, and API listener.

## Reverse proxies

The deployment script deliberately does not edit or reload reverse-proxy
configuration. When another service owns port 443, deploy Porta with
`--port 8443`. A reverse proxy may forward HTTP/2 requests to that TLS listener
for the native multi-lane fallback if it supports unbuffered duplex streaming.
Add `--trust-proxy-headers` when the proxy connects from loopback so
authentication limits use each forwarded client address. Porta ignores those
headers from non-loopback peers. The proxy must replace or safely append
`X-Forwarded-For`; it must also preserve independent backend TCP connections
for the logical lanes. Multiplexing them onto one upstream HTTP/2 connection
defeats most of their loss isolation. Porta logs this condition and increments
`porta_http2_collapsed_lane_groups_total`. Configure an HTTP/1.1 upstream or
connect clients directly when the metric increases. Native MASQUE clients
should use `https://vpn.example.com:8443` directly so UDP traffic reaches Porta.

## Firewall

Allow both protocols on the selected direct port:

```text
TCP 443 (or configured port): HTTP/2 over TLS
UDP 443 (or configured port): HTTP/3/QUIC MASQUE
```

Deployment installs a separate `inet porta_guard` nftables table with an
accept-policy input chain at priority `-10`. It matches only the configured
external interface and Porta port; it does not change the host-wide firewall
policy or rules for Caddy, SSH, or other services. Per-source IPv4 and IPv6
meters drop only excessive new traffic:

- TCP initial SYNs: 200 per second with a 400-packet burst;
- UDP new-flow packets: 500 per second with a 1000-packet burst.

Each dynamic meter is capped at 65,535 source entries with a ten-second source
timeout. Established traffic, unrelated ports, and ICMP/ICMPv6 PMTU feedback
do not match these drop rules. Forwarding/NAT and input-guard tables are
replaced in one nftables transaction and removed together when the service
stops.

The deployment script does not modify UFW, firewalld, Azure NSGs, AWS security
groups, or other cloud perimeter policy. Open the selected TCP and UDP port in
every applicable layer.

For Azure, keep the NSG as the first VM-independent filter:

- allow the Porta port on both TCP and UDP;
- retain TCP 80/443 and UDP 443 only when another service such as Caddy needs
  them;
- keep the loopback admin port closed externally;
- restrict SSH to known administration source ranges;
- remove broad inbound allow rules that make narrower rules ineffective.

An NSG is an L3/L4 allow/deny gate, not a per-source rate limiter. Use Azure
DDoS IP Protection or Network Protection when the public IP needs managed
volumetric-attack mitigation. The NSG, Azure DDoS service, host nftables
meters, transport admission, and authentication limiter protect different
resource boundaries and should be used together.

## Clients and credentials

The first deployment creates a default client using the generated bootstrap
token:

```sh
sudo sed -n 's/^PORTA_TOKEN=//p' /etc/porta/porta.env
```

Use the admin UI for additional clients. Each client receives one random token
that can enroll multiple unique device IDs up to its configured limit. The
registry stores only token hashes in `/var/lib/porta/clients.json`. Disabling a
client, deleting it, or rotating its token cancels its existing VPN lanes and
forward-proxy connections as well as blocking the old credentials. The action
waits for session workers and accounting to finish. Forgetting a device also
disconnects it, but a device with a still-valid shared token can enroll again.
Use **Disconnect now** to end current sessions without changing credentials;
clients with automatic reconnect enabled may reconnect immediately.

## Validation and operations

For a default port-443 deployment:

```sh
sudo systemctl status porta
sudo journalctl -u porta -f
curl http://127.0.0.1:9090/readyz
sudo ss -lntup | grep ':443'
```

For an existing-web-server deployment, replace 443 with 8443 and include
`:8443` in the URL. Static-certificate deployments also install
`porta-cert-sync.timer`:

```sh
sudo systemctl status porta-cert-sync.timer
curl http://127.0.0.1:9090/readyz
```

The expected listeners are TCP and UDP on the configured port. Certificate
synchronization serializes updates, validates the certificate/key pair, and
restores the previous pair if publication fails. New TLS handshakes load the
renewed certificate without disconnecting active tunnels. During a missing or
incomplete replacement, the server retains its last-good certificate and logs
the reload failure and subsequent recovery.

In automatic Let's Encrypt mode, Porta additionally listens on TCP 80 for
HTTP-01 challenges and stores its ACME account and certificates under
`/var/lib/porta/acme`.

`/readyz` returns a component report, not an unconditional success. Required
checks cover the TUN link and gateway address, pool/default routes, IPv4
forwarding, and the deployed Porta nftables forwarding/NAT and public-input
guard rules. The guard check validates its interface, port, protocol, state,
per-source meters, rates, bounds, and drop verdicts. Missing or failed required
checks return HTTP 503. Deployment passes the expected egress interface; manual
runs can set `--egress-interface`. A routed deployment without NAT can use
`--readiness-require-nat=false`. Reverse-proxy backend mode does not require the
public-input guard because its listener must be loopback-only.

Checks share the `--readiness-timeout` budget (default three seconds). Optional
`--readiness-egress-url` and `--readiness-dns-name` probes report outbound HTTP
and resolution through the configured DNS server; their failures are visible
but do not change local readiness. These host-originated probes do not prove
end-to-end client forwarding or validate cloud firewall policy. Arbitrary
third-party firewall rules are not interpreted by the Porta rule checker.

Metrics include `porta_router_dropped_packets_total{reason="..."}` for queue
overflow, closed/missing sessions and invalid TUN packets, plus
`porta_datagram_oversize_total` for datagrams carried by capsule fallback. The
latter is not a dropped-packet counter. HTTP/2 queue diagnostics include
`porta_router_queue_bytes{lane="..."}`,
`porta_router_queue_bytes_high_water{lane="..."}`, and drop reasons
`queue_tail`, `queue_oldest`, and `queue_expired`. A sustained queue or frequent
TCP tail drops indicates that an outer TCP lane cannot drain at the offered
rate; increasing queue limits would add latency rather than fix congestion.
Public admission metrics are
`porta_public_connections{transport="tcp|quic"}`,
`porta_public_connections_total{transport="tcp|quic"}`,
`porta_public_connection_rejections_total{transport="...",reason="..."}`, and
`porta_quic_retries_total`. Authentication pressure is reported by
`porta_abuse_rejections_total{surface="native|proxy|portal|invitation"}`.
Source addresses are never metric labels.

## Android

Install the APK, tap **Add profile**, and enter the direct endpoint:

- Default port 443: `https://vpn.example.com`
- Alternate port: `https://vpn.example.com:8443`

Give the profile a recognizable name and enter the token, then save it and
enable its connection switch. Android generates the immutable device identity
in Android Keystore and reports the device name, with a model-name fallback,
as readable metadata.
The app can store multiple VPN
server profiles with Android Keystore-encrypted tokens, while allowing only one
active connection. The status should show **HTTP/3 MASQUE**. If UDP is blocked,
the app starts an encrypted HTTP/2 control lane and one data lane on the same
configured port, then activates up to two more independent data lanes when
queue pressure, blocked writes, startup delay, or lane failures justify them.
Flows remain pinned to the least-loaded healthy data lane; an individual lane
can reconnect without restarting its healthy siblings.

For the public test deployment:

```text
Portal:  https://porta-dev.i-csu.org:8443
Gateway: https://porta-dev.i-csu.org:8443
```

The default APK is the optimized ARM64 build used by most current phones. Use
`porta-android-armeabi-v7a.apk` for older 32-bit ARM devices or
`porta-android-x86_64.apk` for an emulator. Each APK contains only its
required native Go runtime instead of bundling every Android CPU architecture.

## Removal

Stop and disable the units before removing installed files:

```sh
sudo systemctl disable --now porta.service
sudo systemctl disable --now porta-cert-sync.timer 2>/dev/null || true
sudo /usr/local/libexec/porta/server-down.sh porta0 eth0
```

The cleanup helper fails explicitly if required networking tools are missing,
removes tracked Docker exceptions, and restores the saved host IPv4 forwarding
state instead of leaving the machine configured as a router. Failed network
inventory is not treated as successful cleanup. Docker recovery markers are
retained on errors and retired only after the rules, or their chain, are
confirmed absent.

Credential and lease files are intentionally not removed automatically.
