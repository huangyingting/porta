# Go versus Rust server benchmarks

The benchmark suite compares Porta's Go and Rust server implementations using
the production Go client.

Three servers receive the same four-lane Porta HTTP/2/TLS packet workload:

- `go-porta` uses the production gateway handler, address pool, router, packet
  queues, framing, source validation, and a fake echo TUN;
- `go-direct` is a minimal Go relay with the same validation and echo behavior
  as the Rust prototype;
- `rust-direct` is the Tokio, rustls, and h2 implementation.

With `PORTA_RUST_BENCH_TRANSPORT=h3`, the direct servers instead implement
RFC 9484 Extended CONNECT-IP over HTTP/3, ADDRESS_ASSIGN and route capsules,
and Context ID 0 QUIC datagrams. The Rust implementation pins the upstream
`hyperium/h3` revision that adds `connect-ip`, because that support is newer
than its latest crates.io release.

`PORTA_RUST_BENCH_INFLIGHT` controls the maximum number of outstanding
packets per tunnel. The default of one measures interactive ping-pong latency;
larger values explore pipelining. HTTP/3 datagrams are intentionally
unreliable, so the load generator fails the run if excessive offered load
causes packet loss rather than silently reporting successful operations only.

The load generator uses Porta's production Go client. It establishes four
independent HTTP/2 connections per client, signs the ordinary device headers,
sends valid 1,200-byte IPv4 UDP packets across changing flows, and verifies one
response for every upload.

Run the repeatable, CPU-pinned comparison:

```sh
PORTA_RUST_BENCH_WORK=/path/out ./experiments/server-benchmark/run.sh
```

`run.sh` measures the isolated prototype data paths. To compare the complete
production servers through a real Linux TUN, registry, usage store, TLS stack,
router, and kernel UDP echo path, run:

```sh
PORTA_PRODUCTION_BENCH_WORK=/path/out \
  ./experiments/server-benchmark/run-production.sh
```

The production benchmark requires passwordless `sudo`, `unshare`, `ip`, `nft`,
OpenSSL, taskset, Python 3, Go, and stable Rust. It runs in a disposable network
namespace and does not alter host networking.

Defaults are five interleaved runs at 1, 16, and 64 concurrent clients, with a
two-second warmup and six-second measurement. Override
`PORTA_RUST_BENCH_REPEATS`, `PORTA_RUST_BENCH_CLIENTS`,
`PORTA_RUST_BENCH_WARMUP`, `PORTA_RUST_BENCH_DURATION`, or
`PORTA_RUST_BENCH_PAYLOAD` as needed.
CPU scaling can be measured with `PORTA_RUST_BENCH_SERVER_CPUS`,
`PORTA_RUST_BENCH_CLIENT_CPUS`, `PORTA_RUST_BENCH_SERVER_THREADS`, and
`PORTA_RUST_BENCH_CLIENT_THREADS`. Use
`PORTA_RUST_BENCH_IMPLEMENTATIONS="go-direct rust-direct"` to omit the
production-shaped context run. HTTP/3 defaults to the two direct relays because
the strict one-response-per-upload check intentionally fails a run if the
production datagram path drops a packet.

The rewrite threshold is a repeatable improvement of at least 10% in median
throughput or p95 latency at equivalent concurrency, without higher server
memory use or protocol-correctness regressions. The analyzer requires at least
three paired runs for every compared concurrency group and two qualifying
groups with 16 or more clients. This local benchmark is a go/no-go screen, not
a substitute for WAN impairment and production load testing.

A single `run.sh` invocation reports only whether that transport qualifies.
Pass both result files to make the full-rewrite decision:

```sh
python3 experiments/server-benchmark/analyze.py h2-results.jsonl h3-results.jsonl
```

## 2026-09-06 result

The comparison ran from base commit `780280f` on a two-core/four-thread host.
The server and client each had an isolated physical core. `2 SMT` means both
hardware threads of that core were available; `1 thread` means one hardware
thread was pinned. Each median below is from five interleaved runs with one
outstanding 1,200-byte packet per client, a one-second warmup, and a four-second
measurement.

| Transport | CPU setting | Clients | Go ops/s | Rust ops/s | Rust throughput | Go p95 us | Rust p95 us | Rust p95 | Go/Rust RSS MiB |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| HTTP/2 | 2 SMT | 1 | 4,606 | 5,401 | +17.3% | 260.8 | 229.7 | +11.9% | 19.0 / 6.6 |
| HTTP/2 | 2 SMT | 16 | 14,028 | 12,758 | -9.1% | 3,171.9 | 3,152.4 | +0.6% | 23.5 / 8.9 |
| HTTP/2 | 2 SMT | 64 | 42,190 | 49,613 | +17.6% | 4,928.4 | 3,396.3 | +31.1% | 44.7 / 16.1 |
| HTTP/2 | 1 thread | 16 | 13,942 | 13,530 | -3.0% | 3,380.4 | 3,186.3 | +5.7% | 21.6 / 8.8 |
| HTTP/2 | 1 thread | 64 | 33,060 | 33,814 | +2.3% | 4,912.0 | 4,548.9 | +7.4% | 44.2 / 16.2 |
| HTTP/3 | 2 SMT | 1 | 8,896 | 11,211 | +26.0% | 128.7 | 103.1 | +19.9% | 19.4 / 7.1 |
| HTTP/3 | 2 SMT | 16 | 27,736 | 37,440 | +35.0% | 1,933.2 | 1,458.3 | +24.6% | 21.7 / 9.6 |
| HTTP/3 | 2 SMT | 64 | 29,378 | 39,075 | +33.0% | 6,593.9 | 5,233.8 | +20.6% | 32.2 / 16.5 |
| HTTP/3 | 1 thread | 64 | 25,067 | 29,705 | +18.5% | 6,275.8 | 5,681.4 | +9.5% | 29.9 / 16.3 |

Rust cleared the prototype threshold for HTTP/3 and used 49-65% less memory.
HTTP/2 prototype results were mixed, so the production implementation was
measured again after the complete router, persistence, authentication, and
server lifecycle were integrated.

## 2026-09-07 production result

Three interleaved runs used the complete Go and Rust servers, the production Go
client, a real TUN, a kernel-routed UDP echo path, one outstanding 1,200-byte
packet per client, and two SMT threads per process. Negative latency, CPU, and
RSS changes favor Rust.

| Transport | Clients | Rust throughput | Rust p95 | Rust CPU | Rust RSS |
|---|---:|---:|---:|---:|---:|
| HTTP/2 | 1 | -3.1% | -8.5% | -38.0% | -47.9% |
| HTTP/3 | 1 | +34.6% | -31.5% | -38.8% | -50.4% |
| HTTP/2 | 16 | +29.5% | -26.7% | -0.9% | -55.9% |
| HTTP/3 | 16 | +34.5% | -26.6% | -13.7% | -54.5% |

The integrated Rust server has 3.1% lower single-client HTTP/2 throughput, but
improves its latency by 8.5%, CPU by 38.0%, and RSS by 47.9%. It clears the
throughput threshold for HTTP/3 and concurrent HTTP/2 while improving latency
and memory in every measured case. It is now the production build; the Go
server remains available only as an explicit rollback build during deployment
acceptance.
