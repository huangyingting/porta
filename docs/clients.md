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

Make the downloaded binary executable, then run it as an account permitted to
create and configure a TUN interface:

```sh
chmod +x porta-client-linux-amd64
sudo PORTA_TOKEN="CLIENT_TOKEN" ./porta-client-linux-amd64 \
  --server https://vpn.example.com:8443 \
  --client-id my-linux-pc
```

HTTP/3 MASQUE is the default transport. Use `--transport h2` where UDP is not
available. Use `--ca` for a private CA or `--thumbprint` for an exact
certificate pin; do not disable verification in production.

The CLI keeps an established tunnel connected with bounded retry delays.
Authentication and initial configuration errors return immediately. A changed
gateway address or lease requires a fresh start so operating-system routes do
not silently point at stale state.

## Windows

Extract `porta-client-windows-amd64.zip`. It contains:

- `porta.exe`: the desktop client
- `porta-cli.exe`: the command-line client
- `wintun.dll`: the signed Wintun driver library

Launch `porta.exe` for normal use. It requests administrator access, stores
multiple profiles under the current Windows account, protects tokens with
DPAPI, configures routes and DNS, and restores Porta-owned network state on
disconnect or after an interrupted run.

For terminal automation:

```powershell
$env:PORTA_TOKEN = "CLIENT_TOKEN"
./porta-cli.exe `
  --server https://vpn.example.com:8443 `
  --transport h3 `
  --interface Porta `
  --client-id my-windows-pc
```

The CLI leaves route policy under operator control. While it is connected, run
the route helper from another elevated PowerShell session:

```powershell
./scripts/windows-up.ps1 `
  -AddressCidr 10.66.0.2/32 `
  -ServerIp 203.0.113.10 `
  -InterfaceAlias Porta `
  -DnsServer 1.1.1.1
```

Remove those settings with:

```powershell
./scripts/windows-down.ps1 -InterfaceAlias Porta
```

The helpers journal owned routes in
`%LOCALAPPDATA%\Porta\manual-network-state.json`. Keep this file until cleanup
succeeds; it lets the down helper remove the gateway escape route without
deleting an existing route owned by another application. If a cleanup command
fails, its state is retained for retry. An alternate `-StatePath` must be
supplied consistently to both helpers.

For a private certificate, prefer `--ca` or an exact SHA-256 `--thumbprint`.
Do not pin an automatically renewed Let's Encrypt leaf certificate because its
thumbprint changes at renewal.

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
