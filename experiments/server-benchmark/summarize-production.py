#!/usr/bin/env python3
import json
import statistics
import sys


rows = [json.loads(line) for line in open(sys.argv[1], encoding="utf-8")]
print("| Transport | Clients | Throughput | p95 latency | CPU | RSS |")
print("|---|---:|---:|---:|---:|---:|")
for clients in sorted({row["clients"] for row in rows}):
    for transport in ("h2", "h3"):
        values = {}
        for implementation in ("go", "rust"):
            selected = [
                row
                for row in rows
                if row["clients"] == clients
                and row["transport"] == transport
                and row["implementation"] == implementation
            ]
            if not selected:
                break
            values[implementation] = {
                key: statistics.median(row[key] for row in selected)
                for key in (
                    "operations_per_second",
                    "latency_p95_us",
                    "server_cpu_cores",
                    "server_max_rss_kib",
                )
            }
        if len(values) != 2:
            continue
        go = values["go"]
        rust = values["rust"]

        def delta(key):
            return (rust[key] / go[key] - 1) * 100

        print(
            f"| HTTP/{transport[-1]} | {clients} | {delta('operations_per_second'):+.1f}% "
            f"| {delta('latency_p95_us'):+.1f}% | {delta('server_cpu_cores'):+.1f}% "
            f"| {delta('server_max_rss_kib'):+.1f}% |"
        )
