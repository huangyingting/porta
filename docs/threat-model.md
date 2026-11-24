# Threat model and operating boundaries

## Protected properties

- TLS 1.3 protects HTTP/3 traffic; the TLS configuration also permits the TLS
  version required by HTTP/2 implementations.
- A bearer token hash is checked in constant time before a lease is allocated.
- Native tunnel clients also prove possession of an ECDSA P-256 private key on
  every request. The signature binds the account-token hash, HTTP method and
  path, fingerprint ID, readable name, timestamp, and random nonce. The server
  rejects timestamps outside five minutes and duplicate nonces seen by the
  running process.
- The client registry persists SHA-256 token hashes only; newly generated
  tokens are displayed once to the administrator. Bounded eight-hour client
  browser sessions retain encrypted token material in server memory so the
  authenticated download page can display profile setup. The session key is
  process-local, with client identity and token hash authenticated as binding
  data. A separate admin token protects the loopback management API.
- Shared download invitations encrypt the client token and ID using
  AES-256-GCM, a purpose-separated administrator-derived key, and HTTPS-origin
  binding. They survive restart with the same admin token and remain valid
  until revoked, but are reusable bearer credentials, not public or single-use
  links.
  Client rotation, disable, and deletion are checked on redemption and on
  subsequent authenticated page access. Changing the admin token invalidates
  outstanding invitations.
- The gateway rejects packets whose IPv4 source does not equal the session's
  lease, preventing one client from spoofing another client address.
- Packet lengths, IP versions, header lengths, total lengths, and destinations
  are validated before packets cross trust boundaries.
- The direct listener caps accepted TCP and QUIC connections before expensive
  application work. Both transports have per-source connection caps, HTTP/2
  and QUIC stream/window bounds are explicit, and QUIC address validation becomes
  mandatory only when the bounded unvalidated-handshake budget is exhausted.
- Authentication failures use a bounded per-source and per-surface token
  limiter. Successful authentication refunds its reservation, so established
  sessions do not consume failure budget. Overflow uses fixed shards rather
  than allocating unbounded attacker-controlled state.
- Tokens are accepted through environment variables or the admin UI, never
  through client process arguments, and are never intentionally logged.
- Release hashes are covered by a detached signature. Deployment first verifies
  the signing certificate against the repository pin, then verifies the
  manifest signature, and only then trusts artifact hashes. The same pinned
  certificate identifies official Android release APKs.
- Windows verifies the exact Wintun DLL hash while retaining a non-writable
  handle through library loading. Its privileged recovery state lives in
  administrator-only, high-integrity ProgramData storage that rejects reparse
  points and hard links. The embedded PowerShell helper is delivered over
  standard input instead of a replaceable user-writable script and runs with a
  reconstructed system-only environment.
- The access invitation travels in a URL fragment, which is removed before
  same-origin POST redemption. Pages use no-store, restrictive CSP, and secure
  HttpOnly session cookies. The join page uses `Referrer-Policy: same-origin`
  so browsers preserve the POST's Origin for validation; other portal pages use
  `no-referrer`. Neither sends cross-origin referrers. Profile QR payloads contain the
  client token; protect screenshots, downloaded access QR images, copied
  setup text, clipboard history, and messages as credentials. These controls
  do not protect a compromised browser, server process, or recipient device.

## Operator responsibilities

- Keep the admin listener bound to loopback and access it through an SSH tunnel.
  Use independent random admin and client tokens. Keep `PORTA_ADMIN_TOKEN` as
  a break-glass credential and give each administrator a named account with
  the least role they need, two-factor authentication or single sign-on.
- Protect `/var/lib/porta/admins.json` (password hashes and TOTP secrets) and
  `/var/lib/porta/audit.log`; both are written `0600` for the service user.
  Ship the audit log off the host if it must survive a host compromise. The server can obtain its
  certificate from Let's Encrypt or load an externally managed certificate;
  clients validate either through their system trust store.
- When using automatic Let's Encrypt certificates, protect and persist the ACME
  cache directory and expose the challenge listener only as required.
- Keep the daemon unprivileged. It runs as the `porta` user with only network
  capabilities; a compromise can read the TLS key, tokens held in memory, and
  `/var/lib/porta`, and can change network configuration, but cannot write
  configuration, binaries, or the root-only network helper journals.
- Restrict gateway egress, rate-limit the public endpoint, rotate credentials,
  and retain only privacy-appropriate operational logs.
- Apply cloud-edge allow rules and managed DDoS protection where available.
  Deployment owns only Porta's narrowly scoped host nftables tables and does
  not configure the provider firewall.
- Review the NAT script for the host's real external interface. Running a VPN
  gateway can turn a compromised credential into an egress relay.
- Ensure use is permitted by the network owner and applicable law.

## Observable properties

Porta is not undetectable. Network operators can observe endpoint IPs, TLS and
QUIC handshakes, connection duration, packet sizes, timing, and traffic volume.
Endpoint security software can observe the VPN API, TUN interface, routes, and
process. The project does not include browser-fingerprint mimicry, domain
fronting, traffic-shape forgery, or mechanisms intended to defeat an explicit
security policy. Bundled and operator-provided browser landing templates do
not conceal transport fingerprints from network inspection.

## Operational boundaries

- Client accounts identify administrative access groups, not human users.
  Devices sharing one token have equal network privileges.
- Native clients generate their signing keys locally. The public-key
  fingerprint is the immutable enrollment ID; the normalized Android
  device/model name or Windows/Linux machine name is mutable metadata and may
  reveal a user-chosen label. Duplicate names coexist and renaming does not
  create another enrollment.
- Android Keystore keys are non-exportable through normal APIs and may be
  StrongBox/hardware-backed, but Porta does not verify an attestation chain.
  Windows uses machine-bound DPAPI, which prevents an identity file copied to a
  different machine from decrypting. Linux stores a mode-0600 software key,
  which a privileged attacker can copy. Clearing app data, uninstalling, or
  deleting an identity file creates a new enrollment. Modified clients,
  compromised endpoints, local privilege, and server compromise remain outside
  the guarantee. Device quotas count enrolled keys, not attested physical
  hardware.
- Replay nonces are cached only in server memory. After a restart, a captured
  request proof could be replayed until its five-minute timestamp window
  expires. TLS normally prevents network capture; a reverse proxy terminating
  TLS can observe both the bearer token and proof and must be fully trusted.
- With the default `open` enrollment policy, anyone holding an account token
  can enroll new devices up to the device limit. The `approval` and `closed`
  policies make enrollment an administrator decision; approval is keyed by the
  device's public key, not by attested hardware.
- Forward-proxy Basic usernames are ignored, so every proxy client using an
  account token shares one token-only `forward-proxy` enrollment and cannot be
  managed or attributed individually.
- The host input guard limits excessive new packets on Porta's configured
  interface and port. It is not volumetric DDoS protection: traffic still
  reaches the VM, distributed sources can stay below each source limit, and
  cloud-edge filtering remains an operator responsibility.
- The HTTP/2 DATAGRAM-capsule transport inherits TCP head-of-line blocking.
  HTTP/3 uses QUIC Datagrams and therefore does not serialize packet delivery
  on the CONNECT stream, but Datagrams may be lost or reordered.
- Default automatic MTU selection is bounded and authenticated, not continuous
  path-MTU discovery or a guarantee that a path will never change. Lost probes
  cannot raise the interface MTU. A later QUIC payload-limit reduction lowers
  the send budget and uses IPv4 fragmentation or rate-limited DF feedback.
  Non-adapting DF flows have a bounded-state, explicitly reported reliable
  compatibility escape; it retains stream head-of-line blocking. Independent
  bounded writers prevent that backpressure from monopolizing active receive
  processing. None of this repairs a path unable to carry QUIC's minimum UDP
  packet size. Fragmented packets can still be lost or reordered.
- MTU ICMP feedback, in fixed and automatic modes, permits locally sourced
  ingress only on the owned server TUN, using `accept_local=1` and loose
  `rp_filter=2`. Incoming
  client packet sources must still match their authenticated lease. Physical
  interfaces and global reverse-path filtering are not weakened.
- A cascade relay is not an anonymity network. Every hop terminates TLS and
  sees the inner IPv4 packets it forwards, and each relay authenticates to its
  next hop as one device with a stored token and software key. The exit sees
  all relayed clients as that one device. Relay hops limit which public address
  the Internet observes and where traffic exits, not which operators can
  observe it. The upstream interface accepts only replies to relayed flows;
  the next hop cannot use it to reach the relay's host or networks.
- Gateways drop client traffic to link-local addresses, including cloud
  instance metadata, and to gateway host services other than ICMP and DNS
  unless `--client-host-access` is set. Other private networks routed from the
  gateway, such as its cloud VPC, remain reachable by design for remote access;
  restrict them with additional operator firewall rules when not intended.
- Devices of one account reach each other, and accounts that share an access
  group reach each other's devices and subnets. `--client-to-client` makes
  every client of a gateway, across all accounts, a peer. Leave it off unless
  all clients are mutually trusted; client hosts must protect their own
  services from their peers.
- **Allow local network** sends traffic for the attached private networks,
  and their multicast and broadcast, outside the tunnel. On an untrusted
  network, such as public Wi-Fi, that traffic is visible to the network and
  local hosts can reach the device, as without a VPN. Leave the option off
  on profiles used on networks you do not trust.
- With `--peer-to-peer`, peers learn each other's public IP addresses and
  traffic between them bypasses the gateway: it is not logged, counted
  toward usage or quotas, or rate limited there. Peers authenticate each
  other only through fingerprints the gateway vouches for, so a compromised
  gateway can impersonate peers either way. Each client drops direct
  packets that are not from the peer's tunnel addresses to its own.
- Backup archives (`porta-backup`, `/var/backups/porta`) hold every gateway
  secret: tokens, TLS and ACME keys, administrator TOTP secrets and a relay's
  device key. They are root-only on the host; encrypt them before they leave
  it, and treat a leaked archive like a leaked admin token.
- `PORTA_FEDERATION_TOKEN` lets its holder download every account's token
  hash, devices and policies from a primary; token hashes are SHA-256 of
  random tokens and cannot be reversed, but treat the federation token like
  the admin token. Replicas trust what the primary serves.
- The built-in resolver reveals device names and addresses only to a
  device's peers, but every name a client looks up is visible to the gateway
  and to the resolvers it forwards to.
- A subnet router exposes its LAN to its peers. Its LAN hosts can initiate
  connections to peers, as with WireGuard `AllowedIPs`; restrict them with
  deny lists or host firewalls. Source validation is relaxed only for the
  router's own assigned subnets.
- Native clients mitigate fallback head-of-line blocking with independent
  HTTP/2 connections, a prioritized control lane, bounded queues, and
  flow-pinned data lanes. Loss can still stall every flow assigned to the
  affected lane, and a reverse proxy can accidentally collapse the lanes onto
  one backend TCP connection.
- Android prefers native HTTP/3 Extended CONNECT through the bundled Rust
  transport. It falls back to the private adaptive multi-lane HTTP/2
  transport when UDP or HTTP/3 is unavailable.
- Android relies on the system trust store and does not offer an insecure TLS
  switch.
- Linux automatic networking uses an owned nftables OUTPUT guard. Windows
  desktop and CLI automatic networking use persistent native WFP filters.
  Protection starts after the initial DNS/authenticated handshake, before route
  installation.
- Guards remain active on reconnect, process crash, and terminal failure.
  Android retains an established VPN in a packet-dropping blocked state after
  a terminal reconnect failure.
  Intentional disconnect/cleanup restores owned networking and removes the
  guard last. A recovery journal is essential; deleting it is not cleanup.
- Linux protection covers the host's network namespace, not forwarded/container
  traffic. Its exact endpoint TCP/UDP exceptions are not process-specific.
  Windows endpoint exceptions are application scoped and forwarding is blocked.
  Neither implementation overrides unrelated firewall blocks.
- Standard CONNECT-IP clients, allowed per account and off by default,
  authenticate with the token alone. For those accounts a stolen token is
  sufficient to connect (as for the forward proxy); device enrollment,
  approval and per-device revocation do not apply to them.
- IPv6 payload is tunneled only with an IPv6 lease and otherwise blocked in
  full tunnels; split tunnels leave untunneled IPv6 on the device's network.
  On the gateway IPv6 leaves only through the physical interface, never a
  named exit or cascade next hop: those devices get no IPv6 address and a
  cascade relay refuses an IPv6 pool. Loopback and narrowly required
  transport/control exceptions remain. Protected retries use cached literal
  endpoints and retain TLS hostname verification; arbitrary DNS changes,
  physical DHCP renewal, and unrestricted network handover are not guaranteed.
- Process-crash persistence is not a blanket boot-time protection guarantee.
  Linux reboot/external nftables removal and Windows early boot/BFE shutdown
  are outside the guarantee, as is administrator tampering. Mocked policy and
  cross-platform builds are not native packet-level leak certification.
- The release signing private key is an offline-sensitive trust root shared
  with Android release signing. Compromise requires rotating the pinned
  certificate and deliberately migrating installed Android applications;
  ordinary release assets and checksums cannot authorize that rotation.
