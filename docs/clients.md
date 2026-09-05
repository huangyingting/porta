# Client guide

Porta releases provide Linux clients, a Windows desktop and CLI package, and
per-architecture Android APKs. The deployed browser portal mirrors the matching
release artifacts so end users do not need GitHub access.

## Get a client

Open the deployed Porta URL and enter an active client token. The protected
downloads page shows the server address, client release version, package sizes,
and SHA-256 checksums.

Available packages:

- `porta-client-linux-amd64`
- `porta-client-linux-arm64`
- `porta-client-windows-amd64.zip`
- `porta-android-arm64-v8a.apk`
- `porta-android-armeabi-v7a.apk`
- `porta-android-x86_64.apk`

## Linux CLI

Automatic Linux networking requires root, `iproute2`, `nftables`, and a running
`systemd-resolved`. `/etc/resolv.conf` must point to resolved's local stub file
and contain only its loopback nameservers. Other resolver managers and custom
policy-routing rules are rejected rather than silently left unprotected.

Make the downloaded binary executable, then run:

```sh
chmod +x porta-client-linux-amd64
sudo PORTA_TOKEN="CLIENT_TOKEN" ./porta-client-linux-amd64 \
  --server https://vpn.example.com:8443 \
  --client-id my-linux-pc
```

The CLI configures the assigned IPv4 address, MTU, endpoint escape route,
full-tunnel routes, and per-link DNS automatically. Its owned nftables OUTPUT
guard blocks physical IPv4, IPv6, and DNS bypass while connected or reconnecting.
Use `--manual-network` only when managing all routing, DNS, and protection
yourself.

The private recovery journal defaults to `/var/lib/porta/network-state.json`.
After a crash or terminal error, either reconnect using the same journal or
explicitly restore connectivity:

```sh
sudo ./porta-client-linux-amd64 --cleanup-network
```

Use the same `--network-state /private/path/network-state.json` for connection
and cleanup if overriding the default. Keep the journal until cleanup succeeds.
Cleanup removes only Porta-owned changes and removes the guard last; failed
restoration can be retried.

Automatic Linux networking supports a stable physical connection and the
standard local/main/default routing policy. It does not manage DHCP renewal,
arbitrary gateway migration, containers, forwarded traffic, or other network
namespaces. More-specific physical routes remain intact, but their non-exempt
traffic is blocked rather than leaked.

Use `--ca` for a private CA or `--thumbprint` for an exact certificate pin;
do not disable verification in production.

## Windows

Extract `porta-client-windows-amd64.zip`. It contains:

- `porta.exe`: the desktop client
- `porta-cli.exe`: the command-line client
- `wintun.dll`: the signed Wintun driver library

Launch `porta.exe` for normal use. It requests administrator access, stores
multiple profiles under the current Windows account, protects tokens with
DPAPI, configures routes, DNS, and the negotiated Windows IP-interface MTU,
and restores Porta-owned network state on
intentional disconnect. An interrupted run keeps the guard active; a reconnect
resumes the protected tunnel, while explicit cleanup removes the guard.

For terminal automation with the same automatic networking and protection:

```powershell
$env:PORTA_TOKEN = "CLIENT_TOKEN"
./porta-cli.exe `
  --server https://vpn.example.com:8443 `
  --manual-network=false `
  --interface Porta `
  --client-id my-windows-pc
```

The desktop and automatic CLI journal is
`%APPDATA%\Porta\network-state.json`. After a terminal failure, use **Restore
network** in the desktop client. **Quit** also restores this client's owned
settings and stays open if restoration fails. Alternatively, cleanup can be run
from an elevated terminal:

```powershell
./porta-cli.exe --cleanup-network
# The desktop executable also accepts --cleanup-network.
```

Only one process can own a journal. If the GUI still owns it after an error,
use its Restore network action instead of a competing CLI command. A second
GUI can quit without disrupting another process's active connection.
Disconnect with the
previous client before upgrading an existing connection; old journals that lack
exact ownership information must be restored by the client that created them.

Unlike Linux, the Windows CLI defaults to manual networking for operator
automation; omit `--manual-network=false` only when managing setup yourself.
While the manual CLI is connected, run the route helper from another elevated
PowerShell session using the **same executable path as the transport**:

```powershell
$mtu = [int](Read-Host "MTU printed by the connected porta-cli")
./scripts/windows-up.ps1 `
  -AddressCidr 10.66.0.2/32 `
  -ServerIp 203.0.113.10 `
  -ServerPort 8443 `
  -InterfaceAlias Porta `
  -DnsServer 1.1.1.1 `
  -Mtu $mtu `
  -ClientExecutable ./porta-cli.exe
```

Remove those settings with:

```powershell
./scripts/windows-down.ps1 -InterfaceAlias Porta -ClientExecutable ./porta-cli.exe
```

The helpers use the client's shared native protection implementation and journal
owned networking in
`%LOCALAPPDATA%\Porta\manual-network-state.json`. Keep this file until cleanup
succeeds; it lets the down helper remove the gateway escape route without
deleting an existing route owned by another application. If a cleanup command
fails, its state is retained for retry. An alternate `-StatePath` must be
supplied consistently to both helpers.

Use the assigned address, DNS, and MTU printed by the connected CLI when running
manual setup. Wintun's packet-buffer MTU alone does not configure Windows TCP/IP;
the helper applies the OS MTU and journals its original value for restoration.
Partial MTU changes and interrupted cleanup retain retryable ownership.

The advertised DNS resolver gets its own TUN host route, so a more-specific
physical network prefix cannot divert private DNS. Reconnect preserves that
route, and a DNS change installs its replacement before retiring the old route.

Windows uses persistent Windows Filtering Platform filters in Porta's own
sublayer, not changes to global Windows Firewall defaults. The physical endpoint
exception is executable/IP/port scoped; IPv4 TUN traffic and loopback are allowed,
while other IPv4/IPv6 payload and forwarding are blocked. Required IPv6 neighbor
discovery is permitted when using an IPv6 transport endpoint. Other firewall
blocks remain effective.

Physical DNS and DHCP are not exempted. A physical network change or restrictive
resolver policy may therefore require explicit cleanup and reconnection.
Persistence does not guarantee protection before the Base Filtering Engine
starts, while it is stopped, or against administrator changes. Native Windows
packet-level acceptance remains necessary before treating this as leak
certification.

For a private certificate, prefer `--ca` or an exact SHA-256 `--thumbprint`.
Do not pin an automatically renewed Let's Encrypt leaf certificate because its
thumbprint changes at renewal.

## Desktop transport and protection lifecycle

The default `--transport auto` tries HTTP/3 MASQUE and falls back to HTTP/2
CONNECT-IP when the transport is unavailable. Explicit `--transport h3` and
`--transport h2` disable automatic selection. Authentication, certificate,
wire-version, malformed-control, and invalid-lease failures never justify
downgrading. A lease-assignment timeout is retryable without downgrading.

Transient startup failures and interrupted sessions use bounded retry delays.
Reconnects update endpoint escape routes, address, MTU, and DNS while retaining
protection; address/MTU changes recreate the TUN and discard stale queued
packets. Windows removes the cached adapter exemption during a guarded dial and
revalidates/reapplies networking even when the new lease is unchanged. The
selected transport is reported rather than simply displaying
"automatic".

On a fresh connection, initial hostname resolution and the authenticated
handshake occur **before protection starts**. Protection activates before
tunnel routes are installed. Subsequent retries use cached numeric endpoints
while retaining the original hostname for TLS verification. Crash recovery uses
journaled endpoints without physical DNS. DNS changes introducing entirely new
addresses are not discovered under the guard; an explicit cleanup and fresh
connection may be needed.

Once active, the guard stays across process crashes and terminal failures.
With automatic networking, an explicit Disconnect, normal cancellation, or
`--cleanup-network` restores connectivity. Manual Windows setup requires its
matching down helper. Do not delete the journal to bypass failed cleanup.
Linux guard persistence covers a process crash, not a reboot or external
firewall removal.
Payload tunneling remains IPv4-only; necessary endpoint/control exceptions do
not provide general IPv6 connectivity.

Advertised DNS must be a numeric unicast IPv4 resolver reachable through the
tunnel; private addresses are supported, but loopback and link-local resolvers
are not.

## Tunnel MTU

Native HTTP/3 clients automatically select an MTU by default, from a
conservative 1100 baseline up to the server ceiling (1400 by default).
Only a successful, same-size bidirectional datagram probe permits an increase.
Inconclusive probing keeps the last confirmed value or 1100. Operators can
change the ceiling with `--mtu`, or use `--auto-mtu=false --mtu 1100` for
fixed behavior; clients require no extra option.

Client and server agree before the interface is configured. Linux applies the
final lease MTU, Windows applies it to the Windows IP interface as well as
Wintun, and Android passes it to `VpnService.Builder.setMtu`. Manual desktop
setup must use the MTU printed by the connected CLI, not the server ceiling.
No client-facing MTU toggle is necessary.

The value stays fixed for the connection. Reconnects can choose another MTU;
a change can recreate the desktop TUN and interrupt existing flows. A later
QUIC size-limit reduction uses reliable capsules for affected packets rather
than resizing the live interface. HTTP/2, Android's four-lane fallback, and
HTTP/3 without Datagrams retain the configured server MTU. This setting does
not apply to the HTTPS forward proxy, which has no VPN TUN interface.

The 1100 baseline is not a universal VPN-over-VPN guarantee. QUIC still needs
the outer VPN to carry at least a 1200-byte UDP payload (at least 1228 bytes
with IPv4 or 1248 with IPv6, before IP options/extension headers). A smaller
outer path needs the HTTP/2/TCP transport instead; lowering the inner MTU
cannot repair QUIC's outer minimum. Nested VPNs also require compatible
routing and firewall/kill-switch rules.

## Android

Use `porta-android-arm64-v8a.apk` for most current physical devices,
`armeabi-v7a` for older 32-bit ARM devices, or `x86_64` for an emulator.

Open Porta, tap **Add profile**, and enter:

- a recognizable profile name;
- the direct gateway URL, including the port when it is not 443;
- the client token;
- a stable, unique device ID.

Approve Android's VPN prompt and enable the profile. Android prefers native
HTTP/3 MASQUE. If UDP or HTTP/3 is unavailable, it automatically falls back to
four encrypted HTTP/2 lanes on the same port. Authentication, certificate, and
invalid-configuration failures do not trigger a fallback.

Profiles are stored locally, tokens are encrypted with Android Keystore, and
only one profile can be active. The app supports bounded reconnects, optional
reconnect after device restart, live traffic statistics, and a local diagnostic
log that excludes tokens and authorization headers.

## Forward proxy clients

The HTTPS forward proxy uses a stable device ID as the Basic-auth username and
the client token as the password:

```sh
curl --proxy https://vpn.example.com:8443 \
  --proxy-basic --proxy-user 'laptop:CLIENT_TOKEN' \
  https://example.com/
```

For ZeroOmega, select an **HTTPS proxy**, enter the Porta hostname and port,
use a stable device ID as the username, and use the client token as the
password. Porta supports only HTTPS `CONNECT` to public destinations on port
443; it does not provide a PAC file or cache responses.
