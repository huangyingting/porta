#!/usr/bin/env python3
"""Summarize end-to-end Porta server and client benchmark results."""

import json
import statistics
import sys


def median(selected, field):
    return statistics.median(row[field] for row in selected)


def client_implementation(row):
    return row.get("client_implementation", "go")


def transport_label(transport):
    return f"HTTP/{transport[-1]}" if transport != "auto" else "Automatic"


def percent_change(current, baseline):
    if baseline == 0:
        return "n/a"
    return f"{(current / baseline - 1) * 100:+.1f}%"


def cpu_per_operation(selected, field):
    return median(selected, field) / median(selected, "operations_per_second")


with open(sys.argv[1], encoding="utf-8") as source:
    rows = [json.loads(line) for line in source if line.strip()]
if not rows:
    raise SystemExit("benchmark produced no results")

print(
    "| Client | Transport | Clients | Runs | Throughput | p95 latency | "
    "Client CPU | Client RSS | Server CPU | Server RSS |"
)
print("|---|---|---:|---:|---:|---:|---:|---:|---:|---:|")
implementations = sorted({client_implementation(row) for row in rows})
clients_values = sorted({row["clients"] for row in rows})
for implementation in implementations:
    for clients in clients_values:
        for transport in ("h2", "h3", "auto"):
            selected = [
                row
                for row in rows
                if client_implementation(row) == implementation
                and row["clients"] == clients
                and row["transport"] == transport
            ]
            if not selected:
                continue
            throughput = median(selected, "operations_per_second")
            latency = median(selected, "latency_p95_us")
            client_cpu = median(selected, "client_cpu_cores")
            client_rss = median(selected, "client_max_rss_kib")
            server_cpu = median(selected, "server_cpu_cores")
            server_rss = median(selected, "server_max_rss_kib")
            print(
                f"| {implementation} | {transport_label(transport)} | {clients} | "
                f"{len(selected)} | {throughput:,.0f} ops/s | {latency:,.1f} us | "
                f"{client_cpu:.2f} cores | {client_rss / 1024:.1f} MiB | "
                f"{server_cpu:.2f} cores | {server_rss / 1024:.1f} MiB |"
            )

normalized = {implementation.lower(): implementation for implementation in implementations}
if "go" in normalized and "rust" in normalized:
    print()
    print(
        "| Transport | Clients | Rust throughput | Rust p95 | Rust client CPU/op | "
        "Rust client RSS | Rust server CPU/op | Rust server RSS |"
    )
    print("|---|---:|---:|---:|---:|---:|---:|---:|")
    go_label = normalized["go"]
    rust_label = normalized["rust"]
    for clients in clients_values:
        for transport in ("h2", "h3", "auto"):
            go_rows = [
                row
                for row in rows
                if client_implementation(row) == go_label
                and row["clients"] == clients
                and row["transport"] == transport
            ]
            rust_rows = [
                row
                for row in rows
                if client_implementation(row) == rust_label
                and row["clients"] == clients
                and row["transport"] == transport
            ]
            if not go_rows or not rust_rows:
                continue
            print(
                f"| {transport_label(transport)} | {clients} | "
                f"{percent_change(median(rust_rows, 'operations_per_second'), median(go_rows, 'operations_per_second'))} | "
                f"{percent_change(median(rust_rows, 'latency_p95_us'), median(go_rows, 'latency_p95_us'))} | "
                f"{percent_change(cpu_per_operation(rust_rows, 'client_cpu_cores'), cpu_per_operation(go_rows, 'client_cpu_cores'))} | "
                f"{percent_change(median(rust_rows, 'client_max_rss_kib'), median(go_rows, 'client_max_rss_kib'))} | "
                f"{percent_change(cpu_per_operation(rust_rows, 'server_cpu_cores'), cpu_per_operation(go_rows, 'server_cpu_cores'))} | "
                f"{percent_change(median(rust_rows, 'server_max_rss_kib'), median(go_rows, 'server_max_rss_kib'))} |"
            )
