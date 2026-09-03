# Production deployment

This guide deploys hTun directly on one TCP and UDP port. An existing web
server may continue serving websites and renewing the certificate on port 443,
but native HTTP/3/MASQUE traffic goes directly to hTun and does not pass
through a reverse proxy.

## Choose a deployment mode

| Environment | Command options | Tunnel port | Certificate renewal |
|---|---|---:|---|
| Standalone server | `--domain vpn.example.com` | 443 by default | hTun/Let's Encrypt |
| Another service uses 80/443 | `--domain`, `--cert`, `--key`, `--port 8443` | 8443 | External issuer |
| Custom standalone port | `--domain`, `--port PORT` | Configured value | hTun/Let's Encrypt through TCP 80 |

`--port` controls both the TCP HTTP/2 listener and UDP HTTP/3/QUIC listener.
It defaults to 443. The Android gateway URL must include the port when it is
not 443.

## Prerequisites

- Linux with systemd, nftables, `/dev/net/tun`, and IPv4 forwarding support
- Go 1.26 or a prebuilt `bin/htun-server`
- A DNS hostname pointing to the server
- Either public TCP port 80 for automatic Let's Encrypt issuance, or an
  existing certificate and private key covering the hostname
- Both TCP and UDP on the selected port allowed by host and cloud firewalls

## One-command installation with Let's Encrypt

When no certificate paths are supplied, hTun obtains and renews its own
Let's Encrypt certificate:

```sh
sudo ./scripts/deploy.sh \
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

From a checked-out hTun repository:

```sh
sudo ./scripts/deploy.sh \
  --domain vpn.example.com \
  --cert /etc/letsencrypt/live/vpn.example.com/fullchain.pem \
  --key /etc/letsencrypt/live/vpn.example.com/privkey.pem \
  --port 8443
```

The default deployment:

- listens on TCP and UDP 443;
- uses HTTP/3 MASQUE with HTTP/2 fallback;
- creates `htun0` and the `10.66.0.0/24` client network;
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

The script is idempotent. Re-running it rebuilds and upgrades the server while
preserving `/etc/htun/htun.env`, `/etc/htun/clients`, and persistent leases.
The gateway address is derived from the pool unless explicitly supplied. A
pool change is rejected when existing leases are incompatible; use
`--reset-leases` to archive those leases deliberately. Use `--no-build` to
deploy an existing `bin/htun-server`.

The installer validates port availability before stopping an existing
gateway. If the new service cannot obtain its certificate or pass the
readiness check, it restores the previous systemd configuration and restarts
the previous gateway.

## Reverse-proxy compatibility

The deployment script deliberately does not edit or reload reverse-proxy
configuration. When another service owns port 443, deploy hTun with
`--port 8443`. A reverse proxy may forward HTTP/2 requests to that TLS
listener for compatibility, but Android and other native MASQUE clients
should use `https://vpn.example.com:8443` directly so UDP traffic reaches hTun.

## Firewall

Allow both protocols on the selected direct port:

```text
TCP 443 (or configured port): HTTP/2 over TLS
UDP 443 (or configured port): HTTP/3/QUIC MASQUE
```

The deployment script does not modify UFW, firewalld, Azure NSGs, AWS security
groups, or other perimeter policy. Open the port in every applicable layer.

## Credentials

Retrieve the generated migration token without printing it during deployment:

```sh
sudo sed -n 's/^HTUN_TOKEN=//p' /etc/htun/htun.env
```

For per-device revocation, add credentials to `/etc/htun/clients`:

```text
android-phone=replace-with-a-random-device-secret
windows-laptop=replace-with-another-random-device-secret
```

Restart hTun after changing that file:

```sh
sudo systemctl restart htun
```

After all clients use device credentials, remove `HTUN_TOKEN` from
`/etc/htun/htun.env`.

## Validation and operations

For a default port-443 deployment:

```sh
sudo systemctl status htun
sudo journalctl -u htun -f
curl --resolve vpn.example.com:443:127.0.0.1 \
  https://vpn.example.com/readyz
sudo ss -lntup | grep ':443'
```

For an existing-web-server deployment, replace 443 with 8443 and include
`:8443` in the URL. Static-certificate deployments also install
`htun-cert-sync.timer`:

```sh
sudo systemctl status htun-cert-sync.timer
curl --resolve vpn.example.com:8443:127.0.0.1 \
  https://vpn.example.com:8443/readyz
```

The expected listeners are TCP and UDP on the configured port. Certificate
synchronization replaces the copied files atomically; new TLS handshakes load
the renewed certificate without disconnecting active tunnels.

In automatic Let's Encrypt mode, hTun additionally listens on TCP 80 for
HTTP-01 challenges and stores its ACME account and certificates under
`/var/lib/htun/acme`.

## Android

Install the APK, tap **Add profile**, and enter the direct endpoint:

- Default port 443: `https://vpn.example.com`
- Alternate port: `https://vpn.example.com:8443`

Give the profile a recognizable name, enter the token and a stable device ID,
then save it and enable its connection switch. The app can store multiple VPN
server profiles with Android Keystore-encrypted tokens, while allowing only one
active connection. The status should show **HTTP/3 MASQUE**. If UDP is blocked,
the app automatically uses encrypted HTTP/2 fallback on the same configured
port.

For the public test deployment:

```text
APK:     https://htun.i-csu.org/download/htun-android-0.5.0-debug.apk
Gateway: https://htun.i-csu.org:8443
```

## Removal

Stop and disable the units before removing installed files:

```sh
sudo systemctl disable --now htun.service
sudo systemctl disable --now htun-cert-sync.timer 2>/dev/null || true
sudo /usr/local/libexec/htun/server-down.sh htun0 eth0
```

Credential and lease files are intentionally not removed automatically.
