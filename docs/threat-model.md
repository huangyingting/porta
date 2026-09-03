# Threat model and operating boundaries

## Protected properties

- TLS 1.3 protects HTTP/3 traffic; the TLS configuration also permits the TLS
  version required by HTTP/2 implementations.
- A bearer token hash is checked in constant time before a lease is allocated.
- Client tokens are stored only as SHA-256 hashes; newly generated tokens are
  displayed once. A separate admin token protects the loopback management API.
- The gateway rejects packets whose IPv4 source does not equal the session's
  lease, preventing one client from spoofing another client address.
- Packet lengths, IP versions, header lengths, total lengths, and destinations
  are validated before packets cross trust boundaries.
- Tokens are accepted through environment variables or the admin UI and are
  never intentionally logged.

## Operator responsibilities

- Keep the admin listener bound to loopback and access it through an SSH tunnel.
  Use independent random admin and client tokens. The server can obtain its
  certificate from Let's Encrypt or load an externally managed certificate;
  clients validate either through their system trust store.
- When using automatic Let's Encrypt certificates, protect and persist the ACME
  cache directory and expose the challenge listener only as required.
- Restrict gateway egress, rate-limit the public endpoint, rotate credentials,
  and retain only privacy-appropriate operational logs.
- Review the NAT script for the host's real external interface. Running a VPN
  gateway can turn a compromised credential into an egress relay.
- Ensure use is permitted by the network owner and applicable law.

## Observable properties

Porta is not undetectable. Network operators can observe endpoint IPs, TLS and
QUIC handshakes, connection duration, packet sizes, timing, and traffic volume.
Endpoint security software can observe the VPN API, TUN interface, routes, and
process. The project does not include browser-fingerprint mimicry, domain
fronting, traffic-shape forgery, or mechanisms intended to defeat an explicit
security policy. The browser-facing Porta landing page does not conceal
transport fingerprints from network inspection.

## Known MVP limitations

- Client accounts identify administrative access groups, not human users.
  Devices sharing one token have equal network privileges.
- The HTTP/2 DATAGRAM-capsule transport inherits TCP head-of-line blocking.
  HTTP/3 uses QUIC Datagrams and therefore does not serialize packet delivery
  on the CONNECT stream, but Datagrams may be lost or reordered.
- Android mitigates fallback head-of-line blocking with four independent
  HTTP/2 connections, including a dedicated DNS lane. Loss can still stall all
  flows assigned to the affected lane.
- Android prefers native HTTP/3 Extended CONNECT through the bundled Go
  MASQUE bridge. It falls back to the private four-lane HTTP/2 transport when
  UDP or HTTP/3 is unavailable.
- Android relies on the system trust store and does not offer an insecure TLS
  switch.
- The Windows route setup is explicit rather than automatic. Kill-switch and
  DNS leak protection must be applied by deployment policy.
