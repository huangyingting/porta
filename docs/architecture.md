# Porta architecture

Porta is an authenticated IPv4 tunnel implementing MASQUE `CONNECT-IP` from
RFC 9484 and the Capsule Protocol/HTTP Datagram conventions from RFC 9297. It
is intended for remote access to networks that the operator owns or is
authorized to administer. It does not attempt to impersonate a browser or hide
its protocol fingerprint.

## Data path

```text
Linux TUN / Windows Wintun / Android VpnService
                       |
                  IP tunnel
                       |
          +------------+------------+
          |                         |
   HTTP/3 MASQUE Datagrams    multi-lane HTTP/2 framing
   (capsules when needed)       (native fallback)
          |                         |
          +------------+------------+
                       |
                 Porta gateway
                       |
                   Linux TUN
                       |
            kernel routing + operator NAT
```

The standard MASQUE endpoint is the RFC 9484 default URI template expanded for an
unrestricted tunnel: `/.well-known/masque/ip/*/*/`. HTTP/2 and HTTP/3 requests
use Extended CONNECT with `:protocol=connect-ip` and
`Capsule-Protocol: ?1`.

Native clients prefer that endpoint over HTTP/3. Their HTTP/2 fallback uses
two-byte length-prefixed packets over independent `POST /v1/tunnel` streams
instead of one ordered MASQUE stream, limiting a lost outer TCP segment to the
flows assigned to one lane.

The client sends an ADDRESS_REQUEST capsule for IPv4. The gateway responds with
an ADDRESS_ASSIGN `/32` lease and a ROUTE_ADVERTISEMENT covering IPv4. HTTP/3
IP packets use HTTP Datagrams whose first field is Context ID 0. HTTP/2, and
HTTP/3 peers that do not negotiate Datagrams, carry the same Context-ID-plus-IP
payload in RFC 9297 DATAGRAM capsules.

The gateway enables assigned-source uplink processing before writing
ADDRESS_ASSIGN: a QUIC peer can receive the lease and send its first datagram
before the control write returns. Failed control writes restore the prior
assignment state. Downlink delivery remains gated until the assignment and
route response have been written and flushed.

RFC 9484 does not define DNS or link-MTU negotiation, so the gateway provides
optional `X-Porta-DNS` and `X-Porta-MTU` response extensions. Authentication uses
`Authorization: Bearer <token>`, and `X-Porta-Client-ID` provides stable lease
selection and reconnect replacement. The token identifies a client account,
while the client ID identifies one enrolled device. Their combined identity
prevents device-name collisions between accounts.

### Stable per-connection MTU selection

Automatic MTU selection is enabled by default for HTTP/3 Datagram connections,
using an optional Porta protocol extension. The default ceiling is 1400;
`--mtu` bounds the selected value, and 1100 is the conservative discovery
baseline. Clients require no extra setting. The shared gateway TUN keeps the
configured ceiling. Use `--auto-mtu=false --mtu 1100` to select a fixed MTU
instead; the daemon, deployment script, and network helper support the same
boolean MTU-mode override.

An eligible client sends `X-Porta-MTU-Discovery: 1`. When enabled, the server
responds with the same header containing a random, session-specific
16-byte nonce encoded as 32 hexadecimal characters. Discovery is offered only
when both peers support HTTP Datagrams and the configured ceiling exceeds
1100. Without an offer, `X-Porta-MTU` remains the fixed MTU. With an offer, it
is the ceiling until reliable selection completes.

Discovery happens before ADDRESS_REQUEST and before client TUN creation:

1. Start at 1100. Send a warm-up probe, then try increasing candidates of 1152,
   1200, 1280, 1360, and 1400, including the exact configured ceiling if lower.
2. Each probe is an HTTP Datagram with Context ID 1, the 16-byte nonce, a
   big-endian 16-bit sequence, a big-endian 16-bit candidate MTU, and zero
   padding. Its total length is exactly the candidate MTU plus one byte, just
   like a Context ID 0 IP datagram of that size.
3. The server echoes valid probes unchanged, only as unreliable datagrams.
   A matching echo demonstrates current delivery in both directions. Capsule
   delivery and successfully queueing a send are never sufficient proof.
4. Probing has a 750 ms budget, at most two 150 ms attempts per candidate,
   and stops increasing on loss or a local QUIC payload-limit error. Keep the
   last confirmed value, or 1100 if discovery is inconclusive. The server
   accepts at most 16 valid probes within three seconds of its offer.
5. The client sends Porta-specific `MTU_SELECT` capsule type `0xff7000`;
   the server validates and acknowledges with `MTU_SELECTED` type
   `0xff7001`. Both contain the nonce followed by a big-endian 16-bit MTU.
   Values above 1100 must match an echoed candidate. A committed selection
   cannot change during that connection.

The entire exchange remains inside the normal startup timeout. Lost probes
do not fail the tunnel, but a missing/malformed reliable agreement does not
permit returning a partially configured connection or downgrading transports.
IP downlink delivery is withheld until address assignment completes. The final
lease MTU reaches Linux, Windows, and the Android native bridge before network
configuration.

Each MASQUE session enforces its own MTU. Oversized packets from the shared
TUN are fragmented when IPv4 DF is clear, including correct copied options,
fragment offsets and checksums. With DF set, the gateway sends ICMP
Destination Unreachable / Fragmentation Needed back through TUN toward the
original sender, quoting the original header and advertising the selected
MTU. Forbidden ICMP replies are suppressed; permitted replies are limited to
one per 100 ms per session. The `porta_mtu_packets_total` metric reports
`fragmented`, `icmp_sent`, `icmp_suppressed`, and `icmp_rate_limited` actions;
selected MTUs appear in server logs.

Linux ordinarily rejects TUN ingress sourced from its own gateway address.
Automatic deployment therefore enables `accept_local=1` and loose
`rp_filter=2` on the owned TUN only. The `mtu_feedback` readiness component
requires local-source acceptance and rejects effective strict reverse-path
filtering. Global and physical-interface source-validation settings remain
unchanged; no production raw-socket capability is added.

This is conservative setup-time selection, not a measurement of the absolute
maximum path MTU or continuous tunnel resizing. QUIC manages its own outer
path MTU independently. If its datagram limit later shrinks, ordinary packets
still use the reliable capsule fallback described below. Selection runs again
on reconnect; a changed lease MTU can recreate the client TUN. HTTP/2,
native private HTTP/2 lanes, and HTTP/3 without Datagrams keep the configured
MTU because their streams can segment data without UDP-sized inner packets.

## Protocol compatibility

Porta application releases and the Porta wire protocol are versioned
independently. Every MASQUE and HTTP/2 fallback tunnel request sends
`X-Porta-Version`. The gateway accepts only a supported wire version and
returns `X-Porta-Version`, `X-Porta-Min-Version`, and `X-Porta-Max-Version` on
successful tunnel responses. An incompatible or missing version receives
`426 Upgrade Required` with the same supported-range headers.

The current development protocol is version `2`, and the gateway currently
supports only that version. Client and server release numbers do not need to
match when their supported protocol ranges overlap. A breaking framing,
authentication, lease, or routing change increments the protocol version;
additive behavior should use negotiated capabilities where possible rather
than forcing an application release lockstep.

The persistent client registry stores only SHA-256 token hashes and maintains
an in-memory hash index, keeping authentication lookup independent of account
count. Each account has an enabled state and a device limit. The loopback-only
admin API manages accounts, token rotation, and device enrollment without
restarting the tunnel service. Throttled forward-proxy LastSeen changes are
coalesced and written outside the authentication lock, with a final durable
flush during shutdown.

Traffic accounting uses connection-local atomic counters, so relay reads and
writes do not contend on the usage store lock. Completed sessions request a
short debounced persistence pass, active sessions are checkpointed
periodically, and shutdown performs a final crash-safe flush before returning.

## Gateway routing

The gateway owns one TUN interface for all connected clients. It validates that
the source address of every received IPv4 packet matches the authenticated
lease before writing that packet to TUN. Packets read from TUN are dispatched
by destination address. Duplicate client IDs replace the older session so that
reconnects converge quickly.

Linux forwarding and NAT are deliberately outside the daemon. The supplied
setup script makes these changes explicit and reversible. The daemon itself can
run with only access to `/dev/net/tun` plus the configured TCP/UDP port.

Packet-device reads transfer ownership of their buffers to the caller. The
router and client receive queues pass those buffers onward without another
payload copy. Reusable decoder buffers are used only where TUN writes finish
before the next read; they must never be queued for asynchronous consumers.
Stream encoders reuse header storage and serialize capsule writes and flushes.
HTTP/2 uploads flush bounded batches of packets already in the queue, without
waiting to fill a batch. Queues are bounded by both bytes and packet count,
expire stale traffic, preserve queued TCP prefixes with tail drop, and prefer
new control traffic over replaceable datagrams. New flows choose the
least-loaded healthy data lane and remain pinned until idle expiry. Fragmented
IPv4 datagrams include their fragment identifier in the flow key so all
fragments remain on one lane.

The HTTPS forward proxy keeps each CONNECT tunnel as one ordered TCP stream.
It races interleaved IPv4 and IPv6 destination attempts with a short stagger,
caches only fully validated public DNS answers for 30 seconds, and rejects the
whole answer set if any address is private or reserved. Downstream response
writes are coalesced up to 128 KiB or two milliseconds before a protocol flush;
the final partial buffer is flushed when the copy direction completes.

## Transport behavior

HTTP/3 enables both the HTTP/3 Datagram setting and QUIC Datagram transport.
IP packets are therefore unreliable, independently delivered Datagrams, as
required for the efficient RFC 9484 mode. Control capsules remain on the
reliable Extended CONNECT request stream.

If an IP packet exceeds the current QUIC datagram payload limit, Porta sends
that packet in a DATAGRAM capsule on the same connection instead of
disconnecting the tunnel. Smaller packets continue using datagrams. This
preserves the selected inner MTU without inventing an MTU from outer-packet
overhead; oversized packets temporarily inherit reliable-stream head-of-line
blocking.

HTTP/2 has no unreliable Datagram frame. It carries the Context ID 0 payload in
DATAGRAM capsules on the reliable CONNECT stream. This is interoperable but
inherits TCP head-of-line blocking.

Client establishment has one timeout covering transport setup, request headers,
optional MTU discovery/agreement, ADDRESS_REQUEST writes and ADDRESS_ASSIGN
receipt. Completing establishment
removes that startup deadline; it does not limit the lifetime of a working
tunnel.

## Platform clients

- Linux configures the TUN, endpoint escape and full-tunnel routes, and
  systemd-resolved per-link DNS through an exclusively locked recovery journal.
  An owned nftables OUTPUT guard remains installed during reconnect and cleanup
  removes it last. This covers host traffic, not containers or forwarded traffic.
- Windows calls the official Wintun API through a pinned DLL whose SHA-256 is
  verified before loading. The desktop client configures addresses, DNS and
  routes through an embedded PowerShell helper delivered over standard input,
  not a user-writable script file.
  Persistent native WFP filters provide atomic fail-closed protection in an
  owned sublayer without overriding unrelated firewall blocks. The CLI retains
  the same automatic lifecycle by default; `--manual-network` delegates all
  network configuration and leak protection to the operator. The helper
  explicitly sets the Windows IP-interface MTU: Wintun's buffer MTU does not
  configure the OS network stack. MTU/DNS/routes are journaled for retryable
  recovery under administrator-only, high-integrity ProgramData storage that
  rejects reparse points and hard links. Guarded reconnects revalidate the
  adapter before restoring its exemption.
- Android uses `VpnService` with the shared native Rust transport. The UDP
  socket is protected from the VPN routing loop and bound to Android's selected
  underlying network. Four-lane HTTP/2 remains an automatic fallback.
  Distribution uses stripped per-ABI APKs so each device downloads only one
  Rust library while retaining the complete HTTP/3 implementation.
  Named server profiles and their tokens are stored locally, with tokens
  encrypted by Android Keystore.

Desktop clients default to automatic HTTP/3 selection with HTTP/2 fallback only
for transport unavailability, never authentication, certificate, or protocol
rejection. Protected reconnects prepare a cached numeric endpoint before dialing
while preserving URL authority and TLS identity. Lease/address/MTU changes
reconfigure networking under the guard; native TUN replacement joins workers
and discards stale queued packets when replacement is required. Initial DNS and authenticated bootstrap are
outside the guard. Recovery journals allow crash restart without physical DNS,
but cannot discover previously unknown hostname addresses while protected.

## Native HTTP/2 fallback

The native fallback uses the private media type
`application/x-porta-packets` and two-byte length-prefixed IPv4 packets over
`POST /v1/tunnel`. Clients declare two through four lanes and use independent
HTTP/2 transports so each lane has its own TCP congestion and loss domain.
Lane zero prioritizes DNS, ICMP, TCP acknowledgements, and small control
datagrams. Other flows are pinned across the healthy data lanes. Startup
requires the control lane and one data lane; remaining lanes can join later,
and an interrupted lane reconnects without tearing down healthy siblings.

This reduces, but cannot eliminate, TCP head-of-line blocking or TCP-over-TCP
congestion effects. A reverse proxy that multiplexes logical lanes onto one
backend HTTP/2 connection restores a shared loss domain; the gateway detects
and reports that condition.

## Roadmap

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
