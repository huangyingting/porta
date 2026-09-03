# hTun architecture

hTun is an authenticated IPv4 tunnel implementing MASQUE `CONNECT-IP` from
RFC 9484 and the Capsule Protocol/HTTP Datagram conventions from RFC 9297. It
is intended for remote access to networks that the operator owns or is
authorized to administer. It does not attempt to impersonate a browser or hide
its protocol fingerprint.

## Data path

```text
Windows Wintun                 Android VpnService
       |                               |
MASQUE CONNECT-IP              legacy hTun v1 stream
       |                               |
  +----+-------------------------------+
  |                                    |
HTTP/2 capsules             HTTP/3 QUIC Datagrams
  |                         (capsule fallback)
  +--------------------+---------------+
                       |
                  hTun gateway
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
optional `X-HTun-DNS` and `X-HTun-MTU` response extensions. Authentication uses
`Authorization: Bearer <token>`, and `X-HTun-Client-ID` provides stable lease
selection and reconnect replacement.

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
- Android uses `VpnService`. Its socket factory calls `VpnService.protect()`
  before OkHttp connects, preventing a routing loop. OkHttp does not expose an
  API for the Extended CONNECT `:protocol` pseudo-header, so Android currently
  uses the compatibility endpoint.

## Compatibility protocol

The older protocol uses the private media type
`application/x-htun-packets` and two-byte length-prefixed IPv4 packets over
`POST /v1/tunnel`. It remains tested but is no longer the desktop default.

## Non-goals and future work

Out of scope are IPv6 address assignment, QUIC connection migration across
Android network changes, configurable request scope and split routes,
multi-token identity storage, and a control-plane API. A future Android Cronet
or native QUIC transport can reuse the MASQUE capsule package without changing
the `VpnService` layer.
