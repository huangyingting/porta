# Porta

Porta is an IPv4 VPN and authenticated HTTPS forward proxy built on MASQUE
`CONNECT-IP`. One gateway serves HTTP/2 over TCP and HTTP/3 over QUIC/UDP on
the same port, with clients for Linux, Windows, and Android.

## Deploy

Porta can be deployed from either:

- the small release bundle, recommended for production; or
- a full Git checkout.

In both cases, `scripts/deploy.sh` downloads and verifies the selected release
artifacts by default. Add `--build-local` only when deploying binaries built
from a full source checkout.

Do not copy `deploy.sh` by itself. It also requires the helper scripts in
`scripts/` and service assets in `deploy/`.

### 1. Get the deployment files

**Release bundle:**

```sh
gh release download --repo huangyingting/porta \
  --pattern porta-deploy.tar.gz --pattern SHA256SUMS
grep ' porta-deploy.tar.gz$' SHA256SUMS | sha256sum -c -
tar -xzf porta-deploy.tar.gz
cd porta
export GH_TOKEN=$(gh auth token)
```

The repository is private, so `gh` must be authenticated with read access.

**Full Git checkout:**

```sh
git clone https://github.com/huangyingting/porta.git
cd porta
export GH_TOKEN=$(gh auth token)
```

### 2. Install the gateway

For a standalone server on TCP and UDP 443 with automatic Let's Encrypt:

```sh
sudo --preserve-env=GH_TOKEN ./scripts/deploy.sh \
  --domain vpn.example.com \
  --acme-email admin@example.com
```

If another service manages the certificate or already owns ports 80 and 443,
run Porta directly on another public port:

```sh
sudo --preserve-env=GH_TOKEN ./scripts/deploy.sh \
  --domain vpn.example.com \
  --cert /absolute/path/fullchain.pem \
  --key /absolute/path/privkey.pem \
  --port 8443
```

Allow both TCP and UDP on the selected tunnel port. Automatic Let's Encrypt
also requires public TCP port 80. The installer configures systemd, TUN,
forwarding, NAT, a Porta-scoped nftables input guard, certificate renewal or
synchronization, client downloads, and the loopback operations listener.

The HTTPS forward proxy is enabled by default. Add
`--disable-forward-proxy` only for a VPN-only deployment.

## Use

### Browser portal

Open the deployed URL, such as `https://vpn.example.com:8443`.

- Enter `PORTA_ADMIN_TOKEN` to manage client accounts, tokens, devices, and
  usage.
- Enter an active client token to download the matching Linux, Windows, or
  Android client.

Retrieve the initial tokens on the server:

```sh
sudo sed -n 's/^PORTA_ADMIN_TOKEN=//p' /etc/porta/porta.env
sudo sed -n 's/^PORTA_TOKEN=//p' /etc/porta/porta.env
```

### Linux client

```sh
chmod +x porta-client-linux-amd64
sudo PORTA_TOKEN="CLIENT_TOKEN" ./porta-client-linux-amd64 \
  --server https://vpn.example.com:8443
```

Linux configures routes, DNS, and an owned fail-closed firewall automatically;
root, iproute2, nftables, and systemd-resolved's local stub are required.
Desktop clients default to HTTP/3 with safe HTTP/2 fallback. See the
[client guide](docs/clients.md) for protection boundaries, manual networking,
and `--cleanup-network` recovery after a crash.
Native clients generate a persistent P-256 signing key locally. Its public-key
fingerprint is the immutable device ID; the Android device/model name or
Windows/Linux machine name is separate readable metadata. Renaming a device
updates its displayed name without consuming another enrollment. The private
key is never sent to Porta.

### Windows client

Extract `porta-client-windows-amd64.zip` and launch `porta.exe` as
administrator. Add a profile with the gateway URL and client token. Windows keeps one
machine-protected signing identity and reports the computer name separately.

### Android client

Scan the private access QR shared by your administrator with your phone's camera,
or open the access link. It opens the client download page without asking for an
access key. Install the APK matching your device architecture.

The download page has a separate profile QR: in Porta, choose **Add profile**
then **Scan QR code**, review the server, and save. On the same phone, use
**Copy setup** on the download page, then **Add profile > Paste setup** in Porta.
Imports create a local profile and do not connect automatically. Android keeps
one app-wide signing key in Android Keystore and uses the device name, or model
fallback, only as the readable name. Identity is not imported or editable.
**Enter manually** remains available. Keep both codes private; access links
remain valid until the client token is rotated, disabled, or deleted, while
profile codes contain the client token.
Android uses HTTP/3 when available and falls back to HTTP/2 automatically.

### Forward proxy

Use any Basic-auth username and the client token as the password. Porta ignores
the username and groups all forward-proxy activity for the account under one
`forward-proxy` device:

```sh
curl --proxy https://vpn.example.com:8443 \
  --proxy-basic --proxy-user 'laptop:CLIENT_TOKEN' \
  https://example.com/
```

Only HTTPS `CONNECT` to public destinations on port 443 is supported.

## Operate

```sh
sudo systemctl status porta
sudo journalctl -u porta -f
curl http://127.0.0.1:9090/readyz
```

Re-run `scripts/deploy.sh` to upgrade while preserving credentials, client
records, usage, and leases.

Automatic HTTP/3 tunnel MTU selection is enabled by default, with a 1400
ceiling and a conservative 1100 baseline. Clients require no extra setting.
Use `--auto-mtu=false --mtu 1100` for a fixed MTU. See
[MTU selection](docs/architecture.md#stable-per-connection-mtu-selection)
for fallback, IPv4 handling, and nested-VPN limits.

## Documentation

- [Production deployment](docs/deployment.md)
- [Client guide](docs/clients.md)
- [Architecture and protocol compatibility](docs/architecture.md)
- [Endpoint reference](docs/endpoints.md)
- [Development and releases](docs/development.md)
- [Threat model](docs/threat-model.md)
