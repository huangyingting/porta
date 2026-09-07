#!/usr/bin/env python3
"""Summarize Rust production-server performance benchmark results."""

import json
import statistics
import sys


rows = [json.loads(line) for line in open(sys.argv[1], encoding="utf-8")]
if not rows:
    raise SystemExit("benchmark produced no results")

print("| Transport | Clients | Runs | Throughput | p95 latency | CPU | RSS |")
print("|---|---:|---:|---:|---:|---:|---:|")
for clients in sorted({row["clients"] for row in rows}):
    for transport in ("h2", "h3", "auto"):
        selected = [
            row
            for row in rows
            if row["clients"] == clients and row["transport"] == transport
        ]
        if not selected:
            continue
        throughput = statistics.median(
            row["operations_per_second"] for row in selected
        )
        latency = statistics.median(row["latency_p95_us"] for row in selected)
        cpu = statistics.median(row["server_cpu_cores"] for row in selected)
        rss = statistics.median(row["server_max_rss_kib"] for row in selected)
        label = f"HTTP/{transport[-1]}" if transport != "auto" else "Automatic"
        print(
            f"| {label} | {clients} | {len(selected)} | "
            f"{throughput:,.0f} ops/s | {latency:,.1f} us | {cpu:.2f} cores | "
            f"{rss / 1024:.1f} MiB |"
        )
