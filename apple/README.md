# Porta for iOS and macOS

`apple/` holds the Porta apps for iPhone, iPad and Mac, and PortaKit, the
Swift package they are built on.

```
apple/
  Package.swift                     PortaKit + the CPorta binary target
  Sources/PortaKit/
    DeviceIdentity.swift            Secure Enclave (or keychain) device key
    TunnelSession.swift             connect, send, receive, cancel
    TunnelSettings.swift            NEPacketTunnelNetworkSettings for a session
    TunnelReport.swift              what the extension tells the app
    Profile.swift                   porta://profile setup links
    PortaPacketTunnelProvider.swift the packet tunnel extension
  App/
    project.yml                     XcodeGen spec: the apps and extensions
    Config/Porta.xcconfig           bundle ID and versions
    Shared/                         the SwiftUI app, for iOS and macOS
    Tunnel/                         the packet tunnel extension
rust/porta-apple/                   the C interface (include/porta.h)
```

## The apps

The iOS and macOS apps share one SwiftUI code base and work like the Android
app:

- **Profiles** are system VPN configurations, so they also appear under
  Settings → VPN. Each profile's token is in the keychain, shared only with
  the tunnel extension. Add one by scanning the downloads page's profile QR
  code (iOS), with **Paste setup** after **Copy setup**, by opening a
  `porta://profile` link, or by entering it manually.
- **Options:** backup gateways, a relay address, **Allow local network**
  (`excludeLocalNetworks`) and **Connect automatically** (connect on demand
  on any network; one profile at most).
- **Fail closed:** full tunnels set `includeAllNetworks`, so nothing leaves
  outside the tunnel while it reconnects. When a gateway turns out to use a
  split tunnel, the app saves the profile without it and reconnects once, so
  other traffic keeps using the local network.
- **Status:** the connection, transport, MTU, routing and account limits,
  live traffic, and a log combining the app's and the extension's events.
  The extension answers `TunnelReport.request` messages; why a tunnel
  stopped reaches the app through `fetchLastDisconnectError`, with the same
  denial messages as the other clients.
- English and Simplified Chinese.

The device key is a P-256 key in the Secure Enclave where available,
falling back to a keychain key, in the keychain group the app and extension
share, so both report the same `d-...` device ID. Apple offers no way for a
device to prove its key to a server, so accounts that require
hardware-protected devices refuse Apple devices.

The Mac app is built for the Mac App Store: there, a packet tunnel can be an
app extension. A Mac app distributed outside the store would need its tunnel
as a system extension instead.

## Build

On macOS with Xcode, rustup and XcodeGen (`brew install xcodegen`):

```sh
make build-apple       # apple/build/Porta.xcframework (macOS, iOS, iOS simulator)
make test-apple        # swift test, then an iOS build of PortaKit
make build-apple-apps  # generates the project and builds both apps unsigned
```

CI runs all three on every push. `make test-apple-ffi` runs on Linux: it
links a C program against `libporta.a` and checks the C interface end to end
against a real gateway in network namespaces.

To run the apps from Xcode on your own devices, run `make apple-project`,
create `apple/App/Config/Signing.xcconfig` with your team ID (it is not
committed):

```
DEVELOPMENT_TEAM = ABCDE12345
```

then open `apple/App/Porta.xcodeproj` and run the **Porta-iOS** or
**Porta-macOS** scheme. Network extensions do not run in the iOS simulator,
so use a real iPhone or iPad.

## Setting up the Apple Developer account

Do this once. None of it needs to be shared: the release workflow signs with
an App Store Connect API key kept in GitHub secrets.

1. **Join the Apple Developer Program** at
   <https://developer.apple.com/programs/enroll/> ($99 a year), as an
   individual or, to publish under a company name, as an organization (which
   needs a D-U-N-S number). Note the **Team ID** under **Membership details**
   at <https://developer.apple.com/account>.
2. **Register the two bundle IDs** under **Certificates, Identifiers &
   Profiles → Identifiers → +** → **App IDs** → **App**, each with the
   **Network Extensions** capability:
   - `dev.porta.app`, described as *Porta*;
   - `dev.porta.app.tunnel`, described as *Porta Tunnel*.

   If `dev.porta.app` is already taken, use your own, such as
   `com.example.porta` and `com.example.porta.tunnel`, and change
   `PORTA_BUNDLE_ID` in `apple/App/Config/Porta.xcconfig` to match.
3. **Create the app record** in App Store Connect
   (<https://appstoreconnect.apple.com>) under **Apps → + → New App**: choose
   **iOS** and **macOS**, a name that is free on the App Store (such as
   *Porta Secure Access*; *Porta* alone may be taken), the bundle ID
   `dev.porta.app`, and any SKU, such as `porta`.
4. **Create an API key** under **Users and Access → Integrations → App Store
   Connect API → Team Keys → +**, with **Admin** access, which automatic
   signing needs to create certificates. Download `AuthKey_KEYID.p8`: Apple
   offers it only once. Note the **Key ID** and the **Issuer ID** shown above
   the list.
5. **Add four repository secrets** under the repository's **Settings →
   Secrets and variables → Actions → New repository secret**, or with `gh`
   on the computer that has the key file:

   ```sh
   gh secret set APPLE_TEAM_ID --body ABCDE12345
   gh secret set ASC_KEY_ID --body KEYID12345
   gh secret set ASC_ISSUER_ID --body 00000000-0000-0000-0000-000000000000
   gh secret set ASC_KEY_P8 < AuthKey_KEYID12345.p8
   ```

   Then delete the downloaded `.p8` file, or keep it in a password manager.
   Revoking the key in App Store Connect withdraws the workflow's access.

## Releasing

1. Run the **Apple release** workflow from the repository's **Actions** tab
   on `main`. It builds the tunnel, archives both apps with automatic signing
   and uploads them to App Store Connect (`scripts/upload-apple.sh`). The
   version is `internal/buildinfo/VERSION` and the build number is the
   workflow's run number.
2. In App Store Connect, answer the export compliance question for the build.
   Porta uses standard encryption (TLS 1.3 and QUIC).
3. **TestFlight:** add yourself and other testers under **TestFlight →
   Internal Testing**. Testers install the **TestFlight** app and accept the
   invitation; the Mac build installs through TestFlight for Mac.
4. **App Store:** add the description, screenshots, the support and privacy
   policy URLs, and the review notes. Review notes for a VPN should say what
   the app is for and give the reviewer a profile setup link or a token for
   a working gateway. Then submit each platform for review.

## Using PortaKit directly

An app imports a profile, stores the token in the keychain and saves a
`NETunnelProviderManager`:

```swift
let profile = try Profile(setupLink: scannedLink)
let tunnel = NETunnelProviderProtocol()
tunnel.providerBundleIdentifier = "com.example.porta.tunnel"
tunnel.serverAddress = profile.server
tunnel.passwordReference = tokenPersistentReference
tunnel.providerConfiguration = [
    "identityTag": "dev.porta.device-key",
    "accessGroup": "TEAMID.com.example.porta",
    "backupServers": [],
    "transport": "auto",
    // "relayAddress": "203.0.113.7:8443", // dial a relay that forwards to the gateway
]
tunnel.includeAllNetworks = true   // fail closed for a full tunnel
tunnel.excludeLocalNetworks = true // the "Allow local network" option
```

The extension's principal class is `PortaPacketTunnelProvider` (or a
subclass). It loads the device key, connects to the first gateway that
accepts the device, applies the assigned addresses, routes and DNS (IPv6
included when the gateway is dual-stack, split tunnels routing only their
prefixes), and reconnects with backoff when the tunnel drops. Keys and
tokens live in the data protection keychain, also on macOS.

## C interface

`rust/porta-apple/include/porta.h` is the contract. Calls block, so run them
off the main thread. Statuses are `PORTA_OK`, `PORTA_RETRYABLE` (try again
or another gateway), `PORTA_PERMANENT` and `PORTA_DENIED`, whose message
starts with `account-denied:<code>:` as on the other clients.
`porta_session_info` returns the session's settings as JSON, matching
`SessionInfo`.
