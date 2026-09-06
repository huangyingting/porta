#!/usr/bin/env python3
"""Summarize interleaved Porta Go/Rust server benchmark results."""

import json
from pathlib import Path
import statistics
import sys

MIN_RUNS = 3
REQUIRED_TRANSPORTS = {"h2", "h3"}
CONFIG_FIELDS = (
    "transport",
    "duration_ms",
    "warmup_ms",
    "payload_bytes",
    "inflight",
    "server_cpus",
    "client_cpus",
    "server_threads",
    "client_threads",
)


def median(values):
    return statistics.median(values)


def summarize(values):
    return {
        "operations_per_second": median([row["operations_per_second"] for row in values]),
        "latency_p95_us": median([row["latency_p95_us"] for row in values]),
        "gigabits_per_second": median([row["gigabits_per_second"] for row in values]),
        "cpu_cores": median([row["server_cpu_cores"] for row in values]),
        "rss_mib": median([row["server_max_rss_kib"] for row in values]) / 1024,
    }


def config_key(row):
    missing = [field for field in CONFIG_FIELDS if field not in row]
    if missing:
        raise SystemExit(f"result row is missing configuration fields: {', '.join(missing)}")
    if row["transport"] not in REQUIRED_TRANSPORTS:
        raise SystemExit(f"unknown transport: {row['transport']}")
    return tuple(row[field] for field in CONFIG_FIELDS)


def evaluate_config(configuration, rows):
    description = ", ".join(
        f"{field}={value}" for field, value in zip(CONFIG_FIELDS, configuration)
    )
    print(f"\n## {description}")
    groups = {}
    for row in rows:
        groups.setdefault((row["clients"], row["implementation"]), []).append(row)

    print("| Clients | Implementation | Runs | ops/s median | p95 us median | Gbit/s median | CPU cores | Max RSS MiB |")
    print("|---:|---|---:|---:|---:|---:|---:|---:|")
    summaries = {}
    for key in sorted(groups):
        values = groups[key]
        summary = summarize(values)
        summaries[key] = summary
        print(
            f"| {key[0]} | {key[1]} | {len(values)} | "
            f"{summary['operations_per_second']:.0f} | {summary['latency_p95_us']:.1f} | "
            f"{summary['gigabits_per_second']:.3f} | {summary['cpu_cores']:.2f} | "
            f"{summary['rss_mib']:.1f} |"
        )

    print("\nRust delta versus equivalent Go direct relay:")
    saturated = []
    low_load_regression = False
    insufficient_repetition = False
    matrix_complete = True
    for clients in sorted({row["clients"] for row in rows}):
        rust_rows = groups.get((clients, "rust-direct"))
        go_rows = groups.get((clients, "go-direct"))
        if not rust_rows or not go_rows:
            matrix_complete = False
            if clients >= 16:
                saturated.append(False)
            print(f"- {clients} clients: missing Go or Rust direct rows (does not qualify)")
            continue
        rust_by_repeat = {row["repeat"]: row for row in rust_rows}
        go_by_repeat = {row["repeat"]: row for row in go_rows}
        paired_repeats = sorted(rust_by_repeat.keys() & go_by_repeat.keys())
        if not paired_repeats:
            insufficient_repetition = True
            if clients >= 16:
                saturated.append(False)
            print(f"- {clients} clients: no paired Go/Rust runs (does not qualify)")
            continue
        repeatable = len(paired_repeats) >= MIN_RUNS
        if not repeatable:
            insufficient_repetition = True
        rust = summarize([rust_by_repeat[repeat] for repeat in paired_repeats])
        go = summarize([go_by_repeat[repeat] for repeat in paired_repeats])
        throughput = (rust["operations_per_second"] / go["operations_per_second"] - 1) * 100
        latency = (1 - rust["latency_p95_us"] / go["latency_p95_us"]) * 100
        memory = (rust["rss_mib"] / go["rss_mib"] - 1) * 100
        material = repeatable and (throughput >= 10 or latency >= 10) and memory <= 0
        if clients >= 16:
            saturated.append(material)
        elif throughput < -5 or latency < -5:
            low_load_regression = True
        print(
            f"- {clients} clients: throughput {throughput:+.1f}%, "
            f"p95 latency {latency:+.1f}%, max RSS {memory:+.1f}% "
            f"({'qualifies' if material else 'does not qualify'}"
            f"{'' if repeatable else f'; needs at least {MIN_RUNS} paired runs'})"
        )
    qualified = (
        matrix_complete
        and len(saturated) >= 2
        and all(saturated)
        and not low_load_regression
        and not insufficient_repetition
    )
    transport = configuration[0]
    print(
        f"\n{transport.upper()} configuration: "
        f"{'QUALIFIES' if qualified else 'DOES NOT QUALIFY'}"
    )
    valid = matrix_complete and not insufficient_repetition
    return transport, qualified, valid


def main():
    if len(sys.argv) < 2:
        raise SystemExit("usage: analyze.py RESULTS.jsonl [RESULTS.jsonl ...]")
    rows = []
    seen = set()
    for path in sys.argv[1:]:
        for line in Path(path).read_text().splitlines():
            if not line:
                continue
            row = json.loads(line)
            identity = (
                config_key(row),
                row["clients"],
                row["implementation"],
                row["repeat"],
            )
            if identity in seen:
                raise SystemExit(f"duplicate result row: {identity}")
            seen.add(identity)
            rows.append(row)
    configurations = {}
    for row in rows:
        configurations.setdefault(config_key(row), []).append(row)

    transport_results = {}
    for configuration in sorted(configurations, key=str):
        transport, qualified, valid = evaluate_config(
            configuration, configurations[configuration]
        )
        transport_results.setdefault(transport, []).append((qualified, valid))

    present = set(transport_results)
    if present != REQUIRED_TRANSPORTS:
        missing = ", ".join(sorted(REQUIRED_TRANSPORTS - present))
        print(
            "\nDecision: INCOMPLETE — full Rust parity requires complete h2 and h3 "
            f"results; missing {missing}"
        )
        return
    qualified = all(
        all(valid for _, valid in transport_results[transport])
        and any(result for result, _ in transport_results[transport])
        for transport in REQUIRED_TRANSPORTS
    )
    print(f"\nDecision: {'PROCEED with full Rust parity' if qualified else 'KEEP the Go server'}")


if __name__ == "__main__":
    main()
