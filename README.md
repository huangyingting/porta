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
- Windows Wintun client plus explicit route setup/teardown scripts
- Android HTTP/2 `VpnService` client using protected sockets
- Backward-compatible private stream protocol for Android and older clients
- Real bidirectional HTTP/2 Extended CONNECT and HTTP/3 Datagram tests

Desktop clients use MASQUE by default. The older `POST /v1/tunnel` protocol is
retained behind `--protocol legacy` because OkHttp does not expose the HTTP/2
Extended CONNECT pseudo-header required by `CONNECT-IP`. Details are in
[the architecture document](docs/architecture.md).

## Build and test

Requirements are Go 1.26 or newer. Android builds additionally require JDK 17
and Android SDK 35.

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

## Development gateway

Generate a certificate. The output paths must not already exist:

```sh
./bin/htun-keygen --hosts vpn.example.test,203.0.113.10
```

Use a random token of at least 32 bytes. Pass it through the environment so it
does not appear in the process list:

```sh
export HTUN_TOKEN="replace-with-a-random-32-byte-or-longer-secret"
sudo --preserve-env=HTUN_TOKEN ./bin/htun-server \
  --listen :8443 \
  --cert server.crt \
  --key server.key \
  --interface htun0 \
  --pool 10.66.0.0/24 \
  --dns 1.1.1.1 \
  --mtu 1300
```

The daemon creates `htun0`, but deliberately does not modify forwarding or
firewall state. In another root shell, after reviewing the script, configure
the interface and NAT. Replace `eth0` with the real egress interface:

```sh
sudo ./scripts/server-up.sh htun0 10.66.0.1/24 10.66.0.0/24 eth0
```

Open both TCP and UDP port 8443 at the host and cloud firewalls. Tear down only
the nftables table owned by this project with:

```sh
sudo ./scripts/server-down.sh htun0
```

The current Go HTTP/2 implementation gates Extended CONNECT behind the
official `GODEBUG=http2xconnect=1` compatibility switch. `htun-server` detects
its absence and re-executes itself once with that switch enabled while
preserving existing `GODEBUG` values.

For production, use a certificate trusted by the clients, a service manager,
an unprivileged process with narrowly scoped TUN capabilities, credential
rotation, and gateway egress controls.

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

Enter an `https://` gateway origin, bearer token, and stable client ID, then
approve Android's VPN prompt. The token is passed directly to the private
service and is not saved in preferences.

The debug build trusts system and user-installed certificate authorities to
support local testing. The release build trusts only the Android system trust
store and contains no insecure-TLS switch. Android currently uses the private
HTTP/2 compatibility stream because OkHttp cannot construct an Extended
CONNECT `:protocol=connect-ip` request. A future Cronet or native QUIC transport
can use the same MASQUE capsule and Datagram formats as the desktop client.

## Protocol endpoints

- `GET /healthz` is unauthenticated and returns only `{"status":"ok"}`.
- `CONNECT /.well-known/masque/ip/*/*/` implements the RFC 9484 default URI
  template for unrestricted IPv4 proxying. It requires `:protocol=connect-ip`,
  `Capsule-Protocol: ?1`, a bearer token, and a stable client ID.
- `POST /v1/tunnel` is the authenticated private compatibility protocol used
  by the current Android client.
- A reconnect using the same client ID reuses its lease and replaces the older
  stream.

RFC 9484 does not standardize DNS or link-MTU configuration. hTun sends these
as optional `X-HTun-DNS` and `X-HTun-MTU` response extensions. The default MTU
is 1300 to leave room for QUIC, UDP, IP, and TLS overhead.

Logs contain client IDs, tunnel addresses, remote IPs, and transport names, but
never intentionally contain bearer tokens or packet contents. IPv6 assignment,
configurable split routing, multi-user identity, automatic roaming, and
kill-switch policy are not implemented in this MVP.
