# Threat model and operating boundaries

## Protected properties

- TLS 1.3 protects HTTP/3 traffic; the TLS configuration also permits the TLS
  version required by HTTP/2 implementations.
- A bearer token is checked in constant time before a lease is allocated.
- The gateway rejects packets whose IPv4 source does not equal the session's
  lease, preventing one client from spoofing another client address.
- Packet lengths, IP versions, header lengths, total lengths, and destinations
  are validated before packets cross trust boundaries.
- Tokens are accepted through flags or environment variables and are never
  intentionally logged.

## Operator responsibilities

- Use a random token of at least 32 bytes. The server can obtain its certificate
  from Let's Encrypt or load an externally managed certificate; clients
  validate either through their system trust store.
- When using automatic Let's Encrypt certificates, protect and persist the ACME
  cache directory and expose the challenge listener only as required.
- Restrict gateway egress, rate-limit the public endpoint, rotate credentials,
  and retain only privacy-appropriate operational logs.
- Review the NAT script for the host's real external interface. Running a VPN
  gateway can turn a compromised credential into an egress relay.
- Ensure use is permitted by the network owner and applicable law.

## Observable properties

hTun is not undetectable. Network operators can observe endpoint IPs, TLS and
QUIC handshakes, connection duration, packet sizes, timing, and traffic volume.
Endpoint security software can observe the VPN API, TUN interface, routes, and
process. The project does not include browser-fingerprint mimicry, domain
fronting, traffic-shape forgery, or mechanisms intended to defeat an explicit
security policy. The optional browser-facing landing page only avoids
identifying hTun during casual HTTP visits; it does not conceal transport
fingerprints from network inspection.

## Known MVP limitations

- Bearer tokens identify access, not individual users, unless an operator runs
  separate gateway instances or adds a control plane.
- The HTTP/2 DATAGRAM-capsule transport inherits TCP head-of-line blocking.
  HTTP/3 uses QUIC Datagrams and therefore does not serialize packet delivery
  on the CONNECT stream, but Datagrams may be lost or reordered.
- Android prefers native HTTP/3 Extended CONNECT through the bundled Go
  MASQUE bridge. It falls back to the private HTTP/2 compatibility protocol
  when UDP or HTTP/3 is unavailable.
- Android relies on the system trust store and does not offer an insecure TLS
  switch.
- The Windows route setup is explicit rather than automatic. Kill-switch and
  DNS leak protection must be applied by deployment policy.
