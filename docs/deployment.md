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

- Linux with `curl`, `sha256sum`, systemd, nftables, `/dev/net/tun`, and IPv4
  forwarding support
- A DNS hostname pointing to the server
- Either public TCP port 80 for automatic Let's Encrypt issuance, or an
  existing certificate and private key covering the hostname
- Both TCP and UDP on the selected port allowed by host and cloud firewalls

## Download the deployment bundle

Each tagged GitHub release contains a deployment bundle plus standalone server
and client binaries. Download and verify the latest bundle:

```sh
gh release download latest --repo huangyingting/porta \
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
`--release vX.Y.Z` to pin release `v0.9.0` or newer. Developers working from a
full source checkout can pass `--build-local` instead.

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

Porta's authenticated HTTPS CONNECT proxy is enabled on the same TLS port by
default. Add `--disable-forward-proxy` only when the deployment should provide
VPN service without the proxy.

The default deployment:

- listens on TCP and UDP 443;
- uses HTTP/3 MASQUE with HTTP/2 fallback;
- enables authenticated HTTPS CONNECT proxying;
- creates `porta0` and the `10.66.0.0/24` client network;
- advertises `1.1.1.1` and an MTU of 1100;
- installs narrowly scoped nftables NAT and forwarding rules;
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

The script is idempotent. Re-running it downloads and upgrades the server while
preserving `/etc/porta/porta.env`, `/var/lib/porta/clients.json`, and persistent leases.
The gateway address is derived from the pool unless explicitly supplied. A
pool change is rejected when existing leases are incompatible; use
`--reset-leases` to archive those leases deliberately.

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
and unauthenticated requests retain the camouflage landing behavior.
Authenticated GitHub release downloads remain available as an operator
fallback.

## Forward proxy

The forward proxy uses the same client accounts managed by the admin UI. The
Basic-auth username is a stable device ID and the password is the client token:

```sh
curl --proxy https://vpn.example.com:8443 \
  --proxy-basic --proxy-user 'laptop:CLIENT_TOKEN' \
  https://example.com/
```

Porta supports HTTPS `CONNECT`, including CONNECT over HTTP/2. Ordinary HTTP
proxy requests are rejected, and only public destinations on port 443 are
permitted.
DNS results are checked before dialing, and any private, loopback, link-local,
metadata, multicast, documentation, or benchmark address rejects the request.
Proxy credentials and client-supplied forwarding identity headers are never
sent to the destination.

Valid Basic credentials activate the proxy. Porta returns a standard `407`
challenge only for CONNECT requests so browser extensions can supply stored
credentials. Ordinary unauthenticated requests still fall through to the
landing or unsupported-request behavior.
Configure ZeroOmega with type **HTTPS**, the Porta hostname and port, a stable
device ID such as `chrome-zeroomega` as the username, and the client token as
the password. ZeroOmega supplies the stored credentials after the CONNECT-only
authentication challenge. Porta
does not serve a public PAC file and does not cache proxy responses.

The installer validates port availability before stopping an existing
gateway. If the new service cannot obtain its certificate or pass the
readiness check, it restores the previous systemd configuration and restarts
the previous gateway.

## Landing page and role-based portal

Porta serves a compact, neutral studio landing page to ordinary browser
requests by default. The page contains no VPN, tunnel, gateway, or transport
language. Its single token field routes administrator tokens to the admin
console and active client tokens to the download page. The resulting
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
`--port 8443`. A reverse proxy may forward HTTP/2 requests to that TLS
listener for Android's four-lane fallback if it supports unbuffered duplex
streaming, but native MASQUE clients should use `https://vpn.example.com:8443`
directly so UDP traffic reaches Porta.

## Firewall

Allow both protocols on the selected direct port:

```text
TCP 443 (or configured port): HTTP/2 over TLS
UDP 443 (or configured port): HTTP/3/QUIC MASQUE
```

The deployment script does not modify UFW, firewalld, Azure NSGs, AWS security
groups, or other perimeter policy. Open the port in every applicable layer.

## Clients and credentials

The first deployment creates a default client using the generated bootstrap
token:

```sh
sudo sed -n 's/^PORTA_TOKEN=//p' /etc/porta/porta.env
```

Use the admin UI for additional clients. Each client receives one random token
that can enroll multiple unique device IDs up to its configured limit. The
registry stores only token hashes in `/var/lib/porta/clients.json`. Disabling a
client or rotating its token blocks future connections immediately; existing
tunnel connections end normally or when the service is restarted.

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
synchronization replaces the copied files atomically; new TLS handshakes load
the renewed certificate without disconnecting active tunnels.

In automatic Let's Encrypt mode, Porta additionally listens on TCP 80 for
HTTP-01 challenges and stores its ACME account and certificates under
`/var/lib/porta/acme`.

## Android

Install the APK, tap **Add profile**, and enter the direct endpoint:

- Default port 443: `https://vpn.example.com`
- Alternate port: `https://vpn.example.com:8443`

Give the profile a recognizable name, enter the token and a stable device ID,
then save it and enable its connection switch. The app can store multiple VPN
server profiles with Android Keystore-encrypted tokens, while allowing only one
active connection. The status should show **HTTP/3 MASQUE**. If UDP is blocked,
the app automatically uses four independent encrypted HTTP/2 connections on
the same configured port. DNS uses a dedicated lane and other flows are hashed
across three data lanes to limit TCP head-of-line blocking.

For the public test deployment:

```text
Portal:  https://htun.i-csu.org:8443
Gateway: https://htun.i-csu.org:8443
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

Credential and lease files are intentionally not removed automatically.
