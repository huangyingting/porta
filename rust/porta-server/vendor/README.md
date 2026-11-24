# Vendored Rust dependencies

Porta carries two focused patches that are not yet available from the locked
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

Each directory retains its upstream license and source metadata. The root
`Cargo.toml` selects these copies with Cargo patch entries.

Android's native build inputs include the vendored sources so a patch
invalidates cached JNI artifacts.

Porta previously vendored `quinn-proto` 0.11.17 for the datagram eviction
accounting fix of [quinn-rs/quinn#2806](https://github.com/quinn-rs/quinn/pull/2806),
which double-subtracted evicted payload bytes and panicked connections under
sustained queue pressure. Releases from 0.11.19 include it. The client
integration test `quic_datagrams` still saturates both directions of a real
loopback QUIC connection, verifies that the newest datagrams survive, and
checks that traffic continues after the queue drains, so a regression in a
later release fails CI.
