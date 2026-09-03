# Production deployment

This guide deploys hTun directly on one TCP and UDP port. Caddy may continue
serving websites and renewing the certificate on port 443, but native
HTTP/3/MASQUE traffic goes directly to hTun and does not pass through Caddy.

## Prerequisites

- Linux with systemd, nftables, `/dev/net/tun`, and IPv4 forwarding support
- Go 1.26 or a prebuilt `bin/htun-server`
- A DNS hostname pointing to the server
- A certificate and private key covering that hostname
- Both TCP and UDP on the selected port allowed by host and cloud firewalls

If Caddy manages the certificate, locate its certificate and key files:

```sh
sudo find /var/lib/caddy/.local/share/caddy/certificates \
  -type f \( -name 'vpn.example.com.crt' -o -name 'vpn.example.com.key' \)
```

## One-command installation

From a checked-out hTun repository:

```sh
sudo ./scripts/deploy.sh \
  --domain vpn.example.com \
  --cert /var/lib/caddy/.local/share/caddy/certificates/acme-v02.api.letsencrypt.org-directory/vpn.example.com/vpn.example.com.crt \
  --key /var/lib/caddy/.local/share/caddy/certificates/acme-v02.api.letsencrypt.org-directory/vpn.example.com/vpn.example.com.key
```

The default deployment:

- listens on TCP and UDP 8443;
- uses HTTP/3 MASQUE with HTTP/2 fallback;
- creates `htun0` and the `10.66.0.0/24` client network;
- advertises `1.1.1.1` and an MTU of 1100;
- installs narrowly scoped nftables NAT and forwarding rules;
- installs hardened systemd services;
- synchronizes renewed certificate files every six hours;
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
  --port 9443 \
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

## Caddy compatibility route

The deployment script writes `/etc/htun/Caddyfile.example` but deliberately
does not edit or reload the shared Caddy configuration. Review and merge the
generated site block if HTTP/2 clients must also connect on port 443:

```sh
sudo cat /etc/htun/Caddyfile.example
sudo caddy validate --config /etc/caddy/Caddyfile
sudo systemctl reload caddy
```

This route is only a fallback. Android and other native MASQUE clients should
use `https://vpn.example.com:8443` directly.

## Firewall

Allow both protocols on the direct port:

```text
TCP 8443: HTTP/2 over TLS
UDP 8443: HTTP/3/QUIC MASQUE
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

```sh
sudo systemctl status htun htun-cert-sync.timer
sudo journalctl -u htun -f
curl --resolve vpn.example.com:8443:127.0.0.1 \
  https://vpn.example.com:8443/readyz
sudo ss -lntup | grep ':8443'
```

The expected listeners are TCP 8443 and UDP 8443. Certificate synchronization
replaces the copied files atomically; new TLS handshakes load the renewed
certificate without disconnecting active tunnels.

## Android

Install the APK, enter the direct endpoint such as
`https://vpn.example.com:8443`, enter the token and a stable device ID, then
tap **Connect**. The status should show **HTTP/3 MASQUE**. If UDP is blocked,
the app automatically uses encrypted HTTP/2 fallback.

For the public test deployment:

```text
APK:     https://htun.i-csu.org/download/htun-android-0.4.0-debug.apk
Gateway: https://htun.i-csu.org:8443
```

## Removal

Stop and disable the units before removing installed files:

```sh
sudo systemctl disable --now htun.service htun-cert-sync.timer
sudo /usr/local/libexec/htun/server-down.sh htun0 eth0
```

Credential and lease files are intentionally not removed automatically.
