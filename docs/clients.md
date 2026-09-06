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

## Automatic device identity

Native clients manage one signing identity independently of profiles. They
generate an ECDSA P-256 key locally, derive an immutable `d-...` ID from the
public-key fingerprint, and sign every tunnel request. Porta stores the public
key, fingerprint ID, and readable name; the private key is never uploaded.

| Client | Private-key storage | Readable name |
| --- | --- | --- |
| Linux | `/var/lib/porta/client-identity.json` for root, or the user's config directory; mode `0600` | OS hostname (`os.Hostname()`) |
| Windows desktop and CLI | `%ProgramData%\Porta\client-identity.json`, protected with machine-bound Windows DPAPI | OS computer name (`os.Hostname()`) |
| Android | Non-exportable Android Keystore alias `porta-device-auth-v1`; StrongBox is preferred when available | `Settings.Global.DEVICE_NAME`, falling back to `Build.MODEL` |

Names keep their case and ASCII letters, digits, dots, underscores, and hyphens.
Each run of other characters, including spaces, becomes one hyphen. Leading and
trailing dots, underscores, and hyphens are removed, then the name is limited to
64 characters. For example, `My Tablet` becomes `My-Tablet`. This normalization
affects only the readable name, not the fingerprint ID.

An unavailable desktop hostname, or one containing no usable ASCII letters or
digits, stops connection with an explicit error; network cleanup remains
available. Android falls back to its model name if its device name cannot be
read or normalized, then to `android` if neither name is usable. Fallbacks are
reported in the app log. Reading the Android device name requires no special
permission on standard Android; its availability varies by manufacturer.

There is no editable native device-ID field or `--client-id` override. The
Windows GUI and CLI, different profiles, reconnects, and HTTP/3-to-HTTP/2
fallbacks reuse the locally stored key. The name is read when a connection
starts and retained throughout that connection. Renaming the device changes
only the server-displayed name on the next connection. Different devices may
have identical names because enrollment and limits are keyed by fingerprint.

Deleting the Linux/Windows identity file or clearing/uninstalling the Android
app creates a new key and therefore a new enrollment. Copying the Linux
software-key file also clones that identity. Windows DPAPI prevents an exported
file from decrypting on another machine. Android Keystore keys are normally
non-exportable and may be hardware-backed, but Porta does not request or verify
key attestation. Rooted/modified clients and privileged local attackers remain
outside this identity guarantee. Device limits count enrolled keys, not
provably distinct physical hardware. Forward proxy is the token-only exception
described below.

## Linux CLI

Automatic Linux networking requires root, `iproute2`, `nftables`, and a running
`systemd-resolved`. `/etc/resolv.conf` must point to resolved's local stub file
and contain only its loopback nameservers. Other resolver managers and custom
policy-routing rules are rejected rather than silently left unprotected.

Make the downloaded binary executable, then run:

```sh
chmod +x porta-client-linux-amd64
sudo PORTA_TOKEN="CLIENT_TOKEN" ./porta-client-linux-amd64 \
  --server https://vpn.example.com:8443
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
  --interface Porta
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
than resizing the live interface. HTTP/2, the native multi-lane fallback, and
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

QR onboarding has two steps:

1. In **Porta Control**, create a client or rotate its token. The compact
   token dialog provides **Copy access link** and **Save access QR**, without
   displaying a profile QR. Share the link or downloaded image privately.
   The user scans this first QR with their phone's ordinary camera or opens
   the link; Porta automatically opens the authenticated client download page,
   with no access-key entry. Install the appropriate client from that page.
2. The download page displays a separate profile QR. In the Android app, tap
   **Add profile** (the **+** button), then **Scan QR code**. Allow camera access,
   scan this second code, review the HTTPS server address and profile name,
   and tap **Save**. On the same phone, select **Copy setup** on the download
   page, then **Add profile > Paste setup** in Porta instead.

Scanning and parsing run entirely on-device without Google Play Services or a
network lookup. Clipboard text is read only when **Paste setup** is selected.
Both import methods create a new local profile; they do not
overwrite existing profiles, change TLS verification, enable auto-connect, or
start a tunnel without your approval. Manual server/token copy controls on the
download page and **Enter manually** in the app remain available.

**Treat both QR codes and their copied links like credentials.** The first
access link is encrypted and reusable until the client token is rotated or the
account is disabled or deleted; encryption does not make public sharing safe.
It works only on the HTTPS origin for which it was issued and survives a server
restart if the administrator token is unchanged. Redemption creates an
eight-hour client browser session. The second profile QR contains the actual
client token and has no independent expiry. Anyone who obtains either can
access the account, subject to its device limit.

Rotating the client token, disabling the account, or deleting it revokes access
through existing invitations and browser sessions. Changing the administrator
token invalidates invitations. Already imported profiles follow the account's
current token and enabled state. The registry persists token hashes only;
bounded client browser sessions retain encrypted token material in server
memory to render setup. Administrator browser sessions never display a client
profile QR. If you already have the client token, sign in with it to view the
setup page again instead of rotating solely to redisplay a profile QR.

For manual setup, tap **Add profile**, then **Enter manually**, and enter:

- a recognizable profile name;
- the direct gateway URL, including the port when it is not 443;
- the client token.

Android generates one ECDSA P-256 key under the Android Keystore alias
`porta-device-auth-v1`. It requests StrongBox where Android reports it as
available, then falls back to the ordinary Android Keystore if StrongBox key
generation is unavailable. The same key is shared by all profiles. Clearing app
data or uninstalling normally deletes it, so the next installation creates a
new enrollment.

Android reads `Settings.Global.DEVICE_NAME` when starting a connection. If it
is missing, denied, or unusable after normalization, the app uses `Build.MODEL`,
then `android`. The fallback reason and Android API version are logged without
exception contents. The name is not the device ID: changing it updates metadata
for the existing key. No `ANDROID_ID`, IMEI, serial number, or profile-provided
device ID is used.

There is no device identity in QR/paste configuration. Porta does not currently
send or verify Android key-attestation certificates, so hardware-backed status
is local diagnostic information rather than proof to the server.

Approve Android's VPN prompt and enable the profile. Android prefers native
HTTP/3 MASQUE. If UDP or HTTP/3 is unavailable, it automatically falls back to
independent encrypted HTTP/2 lanes on the same port. Authentication,
certificate, and invalid-configuration failures do not trigger a fallback.

Profiles are stored locally, tokens are encrypted with Android Keystore, and
only one profile can be active. The app supports bounded reconnects, optional
reconnect after device restart, live traffic statistics, and a local diagnostic
log that excludes tokens and authorization headers.

Swipe an inactive profile at least halfway across its card, **right to edit**
or **left to delete**. The action stays armed through a small retreat, gives
haptic feedback, and then animates through; shorter swipes return to their
starting position. Profile cards have no visible Edit/Delete buttons;
equivalent accessibility actions are available on the profile name.
Deletion requires confirmation and is no longer part of the editor. Disconnect
an active or reconnecting profile before editing or deleting it. Deleting a
local profile does not revoke its token or free its server-side device slot;
an administrator must forget the enrollment separately when needed.

The connection summary shows the effective tunnel MTU. **Log** updates while
open and includes connection setup details, MTU selection, assigned address,
DNS, transport, and fallback/retry information. Automatic selection is
distinguished from a server-configured MTU; the value stays fixed until the
next connection. When an HTTP/2 fallback attempt ends, per-lane diagnostics
record drop totals, queue high-water marks, oldest queued-packet age, and
reconnect counts. The log retains the latest 200 events, includes millisecond
timestamps, and offers **Copy log** and **Clear**. Tokens are excluded, but
logs can contain server/network addresses and the device name, so
share them privately.

## Forward proxy clients

The HTTPS forward proxy ignores the Basic-auth username and authenticates only
the client token supplied as the password. All proxy clients using one account
share one logical `forward-proxy` enrollment and one combined usage record:

```sh
curl --proxy https://vpn.example.com:8443 \
  --proxy-basic --proxy-user 'laptop:CLIENT_TOKEN' \
  https://example.com/
```

For ZeroOmega, select an **HTTPS proxy**, enter the Porta hostname and port,
put any value in the required username field, and use the client token as the
password. The username cannot distinguish, limit, disconnect, or report
individual proxy installations. Porta supports only HTTPS `CONNECT` to public
destinations on port 443; it does not provide a PAC file or cache responses.
