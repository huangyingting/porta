# Porta architecture

Porta is an authenticated IPv4 tunnel implementing MASQUE `CONNECT-IP` from
RFC 9484 and the Capsule Protocol/HTTP Datagram conventions from RFC 9297. It
is intended for remote access to networks that the operator owns or is
authorized to administer. It does not attempt to impersonate a browser or hide
its protocol fingerprint.

## Data path

```text
Windows Wintun                 Android VpnService
       |                               |
MASQUE CONNECT-IP              four-lane Porta stream
       |                               |
  +----+-------------------------------+
  |                                    |
HTTP/2 capsules             HTTP/3 QUIC Datagrams
  |                         (capsule fallback)
  +--------------------+---------------+
                       |
                  Porta gateway
                       |
                   Linux TUN
                       |
            kernel routing + operator NAT
```

The standard endpoint is the RFC 9484 default URI template expanded for an
unrestricted tunnel: `/.well-known/masque/ip/*/*/`. HTTP/2 and HTTP/3 requests
use Extended CONNECT with `:protocol=connect-ip` and
`Capsule-Protocol: ?1`.

The client sends an ADDRESS_REQUEST capsule for IPv4. The gateway responds with
an ADDRESS_ASSIGN `/32` lease and a ROUTE_ADVERTISEMENT covering IPv4. HTTP/3
IP packets use HTTP Datagrams whose first field is Context ID 0. HTTP/2, and
HTTP/3 peers that do not negotiate Datagrams, carry the same Context-ID-plus-IP
payload in RFC 9297 DATAGRAM capsules.

RFC 9484 does not define DNS or link-MTU negotiation, so the gateway provides
optional `X-Porta-DNS` and `X-Porta-MTU` response extensions. Authentication uses
`Authorization: Bearer <token>`, and `X-Porta-Client-ID` provides stable lease
selection and reconnect replacement. The token identifies a client account,
while the client ID identifies one enrolled device. Their combined identity
prevents device-name collisions between accounts.

The persistent client registry stores only SHA-256 token hashes. Each account
has an enabled state and a device limit. The loopback-only admin API manages
accounts, token rotation, and device enrollment without restarting the tunnel
service.

## Gateway routing

The gateway owns one TUN interface for all connected clients. It validates that
the source address of every received IPv4 packet matches the authenticated
lease before writing that packet to TUN. Packets read from TUN are dispatched
by destination address. Duplicate client IDs replace the older session so that
reconnects converge quickly.

Linux forwarding and NAT are deliberately outside the daemon. The supplied
setup script makes these changes explicit and reversible. The daemon itself can
run with only access to `/dev/net/tun` plus the configured TCP/UDP port.

## Transport behavior

HTTP/3 enables both the HTTP/3 Datagram setting and QUIC Datagram transport.
IP packets are therefore unreliable, independently delivered Datagrams, as
required for the efficient RFC 9484 mode. Control capsules remain on the
reliable Extended CONNECT request stream.

HTTP/2 has no unreliable Datagram frame. It carries the Context ID 0 payload in
DATAGRAM capsules on the reliable CONNECT stream. This is interoperable but
inherits TCP head-of-line blocking.

The current `golang.org/x/net/http2` server gates Extended CONNECT behind the
official `GODEBUG=http2xconnect=1` switch. The gateway re-executes itself once
with this setting if it is absent. Tests set it before process startup.

## Platform clients

- Windows uses the WireGuard project's Wintun bindings. Interface address,
  DNS, and default routes are configured by a separate PowerShell script so a
  mistaken server address cannot silently cut off the host. MASQUE is the
  default protocol.
- Android uses `VpnService` with a native Go HTTP/3 MASQUE bridge. The UDP
  socket is protected from the VPN routing loop and bound to Android's selected
  underlying network. Four-lane HTTP/2 remains an automatic fallback.
  Distribution uses stripped per-ABI APKs so each device downloads only one Go
  runtime while retaining the complete HTTP/3 implementation.
  Named server profiles and their tokens are stored locally, with tokens
  encrypted by Android Keystore.

## Android HTTP/2 fallback

The Android fallback uses the private media type
`application/x-porta-packets` and two-byte length-prefixed IPv4 packets over
`POST /v1/tunnel`. Android opens four independent HTTP/2 connections for this
fallback, reserves lane zero for DNS, and consistently distributes other IP
flows across three data lanes. Each lane has its own TCP loss domain, reducing
but not eliminating TCP head-of-line blocking. All four lanes are mandatory;
the gateway rejects headerless or partial single-lane requests.

## Production evolution

The following changes require coordinated protocol and operational design, not
isolated transport patches:

1. **IPv6:** add IPv6 lease and route capsules, dual-stack source validation,
   Android/Windows interface configuration, IPv6 forwarding, and tests that
   prevent traffic leaks when only one address family is available.
2. **Split routing:** authenticate server-defined route policy, advertise only
   authorized prefixes, configure platform-specific route exclusions, and
   define DNS behavior for included and excluded destinations.
3. **High availability:** use a shared identity and lease control plane,
   coordinate duplicate-session ownership, and provide a packet-routing layer
   that can deliver return traffic to the instance holding each live tunnel.
   Sharing the JSON lease file between independent servers is not sufficient.
QUIC connection migration, policy management, and a control-plane API remain
future work.
