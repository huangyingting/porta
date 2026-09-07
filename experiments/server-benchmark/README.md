# Server performance regression benchmark

The live benchmark exercises Porta's production Rust server and Rust load
generator over HTTP/2, HTTP/3, and automatic transport selection. It uses a
real Linux TUN, registry, usage store, TLS stack, router, and kernel UDP echo
path, then reports throughput, latency, CPU, and peak RSS for both the client
and server processes.

Run the repeatable, CPU-pinned benchmark:

```sh
PORTA_SERVER_BENCH_WORK=/path/out ./experiments/server-benchmark/run.sh
```

The benchmark requires passwordless `sudo`, `unshare`, `ip`, `nft`, OpenSSL,
GNU time, taskset, Python 3, and stable Rust. It runs in a disposable network
namespace and does not alter host networking.

Defaults are three runs at 1 and 16 concurrent clients, with a 500-millisecond
warmup and one-second measurement. Override `PORTA_SERVER_BENCH_REPEATS`,
`PORTA_SERVER_BENCH_CLIENTS`, `PORTA_SERVER_BENCH_WARMUP`,
`PORTA_SERVER_BENCH_DURATION`, or `PORTA_SERVER_BENCH_PAYLOAD` as needed.
CPU scaling can be measured with `PORTA_SERVER_BENCH_SERVER_CPUS`,
`PORTA_SERVER_BENCH_CLIENT_CPUS`, `PORTA_SERVER_BENCH_SERVER_THREADS`, and
`PORTA_SERVER_BENCH_CLIENT_THREADS`. `PORTA_SERVER_BENCH_TRANSPORTS` selects
`h2`, `h3`, and/or `auto`; setting `PORTA_SERVER_BENCH_AUTO_MTU=true` also
requires every HTTP/3 connection to complete automatic MTU negotiation.
`PORTA_SERVER_BENCH_INFLIGHT` controls outstanding packets per tunnel.

For migration comparisons, provide space-separated `label=executable` entries.
The same Rust server and benchmark sequence are used for every load generator:

```sh
PORTA_SERVER_BENCH_LOADGENS="rust=/path/porta-loadgen go=/path/go-loadgen" \
  ./experiments/server-benchmark/run.sh
```

Paths must not contain spaces. `PORTA_SERVER_BENCH_LOADGEN` and
`PORTA_SERVER_BENCH_LOADGEN_IMPLEMENTATION` select one external implementation.
Without overrides, the runner builds and measures `porta-loadgen` from the Rust
workspace.

## 2026-09-07 Rust client migration result

The final client comparison used the production Rust server, identical
two-thread CPU pinning, one outstanding 1,200-byte packet per tunnel, a
one-second warmup, and a one-second measurement. Each value is the median of
five completed runs. Transient packet loss from the saturating local UDP echo
path was excluded and rerun in a fresh network namespace.

| Transport | Clients | Rust throughput | Rust p95 | Rust client CPU/op | Rust client RSS | Rust server CPU/op | Rust server RSS |
|---|---:|---:|---:|---:|---:|---:|---:|
| HTTP/2 | 1 | +98.3% | -49.1% | -69.2% | -53.0% | -26.3% | +0.4% |
| HTTP/3 | 1 | +21.0% | -21.0% | -44.5% | -53.4% | -12.6% | -0.3% |
| HTTP/2 | 16 | +76.1% | -74.0% | -51.8% | -64.1% | -31.5% | +0.0% |
| HTTP/3 | 16 | +55.5% | -63.7% | -46.4% | -53.7% | -16.3% | +2.8% |

The initial Rust HTTP/2 client still used a linear scan when its 4,096-entry
flow-affinity table filled. The benchmark crossed that boundary at 16 clients,
causing queue expiry and packet loss. Replacing it with an index-linked,
constant-time LRU removed the cliff: five consecutive three-second stress runs
completed without packet loss at a median 46,972 operations per second.

The historical Go-versus-Rust results below are retained as migration evidence.
The obsolete prototype and Go server implementations were removed after the
Rust server became the only supported production server.

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

At this point the integrated Rust server had 3.1% lower single-client HTTP/2
throughput, but improved its latency by 8.5%, CPU by 38.0%, and RSS by 47.9%.
It cleared the throughput threshold for HTTP/3 and concurrent HTTP/2 while
improving latency and memory in every measured case. It became the production
build, and the temporary Go rollback was later removed after deployment
acceptance.

## 2026-09-07 HTTP/2 flow-churn optimization

Sampling the complete server under the changing-flow workload found that the
HTTP/2 lane router scanned all 4,096 tracked flows for every new flow after the
table reached capacity. A bounded index-linked LRU now performs constant-time
lookup, recency updates, insertion, and eviction while preserving existing-flow
lane affinity. The router hotspot fell from roughly 40% of sampled CPU to 1.6%.

Comparing three baseline runs with three optimized runs produced these median
changes:

| Clients | Rust throughput | Rust p95 | Rust CPU | Rust user CPU | Rust RSS |
|---:|---:|---:|---:|---:|---:|
| 1 | +16.0% | -13.1% | -20.2% | -43.6% | -2.6% |
| 16 | +2.2% | -5.4% | -36.3% | -53.6% | -3.9% |

The single-client runs used ten-second measurements; the 16-client runs used
15-second measurements. HTTP/3 bypasses the multi-lane flow table, and its
control runs remained within approximately 2%, as expected.

A fresh production-path HTTP/2 comparison against the then-current Go rollback
server measured:

| Clients | Duration | Rust throughput | Rust p95 | Rust CPU | Rust RSS |
|---:|---:|---:|---:|---:|---:|
| 1 | 10 s | +46.0% | -31.2% | -50.2% | -51.2% |
| 16 | 6 s | +12.6% | -14.4% | -39.3% | -59.8% |

Each row is the median of three completed runs with identical CPU pinning and
duration. Transient packet-loss failures from the local benchmark harness were
discarded and rerun.
