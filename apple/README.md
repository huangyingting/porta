# PortaKit (macOS and iOS)

PortaKit is the foundation for the macOS and iOS apps: a Swift package that
wraps the Rust tunnel and provides a ready-made packet tunnel provider. The
apps themselves (UI, App Store signing and entitlements) are not in the
repository yet.

```
apple/
  Package.swift                     PortaKit + the CPorta binary target
  Sources/PortaKit/
    DeviceIdentity.swift            Secure Enclave (or keychain) device key
    TunnelSession.swift             connect, send, receive, cancel
    TunnelSettings.swift            NEPacketTunnelNetworkSettings for a session
    Profile.swift                   porta://profile setup links
    PortaPacketTunnelProvider.swift the packet tunnel extension
rust/porta-apple/                   the C interface (include/porta.h)
```

## Build

On macOS with Xcode and rustup:

```sh
make build-apple   # apple/build/Porta.xcframework (macOS, iOS, iOS simulator)
make test-apple    # swift test, then an iOS build of PortaKit
```

`make test-apple-ffi` runs on Linux: it links a C program against
`libporta.a` and checks the C interface end to end against a real gateway in
network namespaces.

## Using it

The app imports a profile, stores the token in the keychain and saves a
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
prefixes), and reconnects with backoff when the tunnel drops.

The device key is a P-256 key in the Secure Enclave where available, falling
back to a keychain key; the Rust side only sees its public key and a signing
callback. Share the keychain access group between the app and the extension
so both report the same `d-...` device ID, which the administrator approves
as on other platforms.

## C interface

`rust/porta-apple/include/porta.h` is the contract. Calls block, so run them
off the main thread. Statuses are `PORTA_OK`, `PORTA_RETRYABLE` (try again
or another gateway), `PORTA_PERMANENT` and `PORTA_DENIED`, whose message
starts with `account-denied:<code>:` as on the other clients.
`porta_session_info` returns the session's settings as JSON, matching
`SessionInfo`.
