# Vendored Rust dependencies

Porta carries three focused patches that are not yet available from the locked
upstream releases:

- `h3` is based on hyperium/h3 commit
  `1f3d5295833ad454343f25d55633fb6bee1027b2`. Porta creates request-completion
  bookkeeping before header resolution and exposes whether the peer SETTINGS
  frame has arrived, preventing reset leaks and distinguishing capsule-only
  peers from delayed Datagram settings.
- `hyper` is based on crates.io release `1.11.1`. Porta keeps the HTTP/2
  upgraded send task alive until graceful shutdown is acknowledged, while an
  abandoned or cancelled flow-control-blocked upgrade resets its stream
  immediately.
- `quinn-proto` is based on crates.io release `0.11.17` (archive SHA-256
  `04759210543be93709136e28212294a659ef5001836ff4eab4d663e4529bba83`).
  It includes the exact accounting fix and regression test from
  [quinn-rs/quinn#2806](https://github.com/quinn-rs/quinn/pull/2806), merged as
  `f650e0f213b01ea7bebd60023e5df7df65e5c2bd`. Datagram eviction must decrement
  the payload byte count only once: `DatagramBuffer::pop_front` already owns
  that accounting. The extra subtraction caused underflow and connection
  panics under sustained queue pressure. This workspace-wide patch protects
  the server and every native client, not just the server crate.

Each directory retains its upstream license and source metadata. The root
`Cargo.toml` selects these copies with Cargo patch entries.

The client integration test `quic_datagrams` saturates both directions of a
real loopback QUIC connection, verifies that the newest datagrams survive,
and checks that traffic continues after the queue drains. Android's native
build inputs include the vendored sources so a patch invalidates cached JNI
artifacts. Remove the Quinn override only after adopting a published release
that includes the upstream fix and passing this regression on that release.
