#!/usr/bin/env bash
set -euo pipefail

for command in go ip tc sudo unshare; do
	if ! command -v "$command" >/dev/null 2>&1; then
		echo "required command not found: $command" >&2
		exit 1
	fi
done
if ! sudo -n true 2>/dev/null; then
	echo "passwordless sudo is required for an isolated network namespace" >&2
	exit 1
fi

work_dir=$(mktemp -d)
test_binary="$work_dir/tunnel.test"
cleanup() {
	rm -f "$test_binary"
	rmdir "$work_dir"
}
trap cleanup EXIT

go test -c -o "$test_binary" ./internal/tunnel

read -r -a rtts <<<"${PORTA_BENCH_RTT_MS:-20 80 150}"
read -r -a losses <<<"${PORTA_BENCH_LOSS_PERCENT:-0 0.5 1 2}"
read -r -a rates <<<"${PORTA_BENCH_RATES:-20mbit 100mbit}"
count=${PORTA_BENCH_COUNT:-1}
packets=${PORTA_BENCH_PACKETS:-200}
timeout=${PORTA_BENCH_TIMEOUT_SECONDS:-5}
pacing=${PORTA_BENCH_PACING_MICROS:-500}

for rtt in "${rtts[@]}"; do
	for loss in "${losses[@]}"; do
		for rate in "${rates[@]}"; do
			echo "=== RTT=${rtt}ms loss=${loss}% rate=${rate} ==="
			sudo -n unshare --net -- bash -ceu '
				ip link set lo up
				one_way=$(( ($2 + 1) / 2 ))
				tc qdisc add dev lo root netem delay "${one_way}ms" loss "$3%" rate "$4" limit 1000
				PORTA_TRANSPORT_IMPAIRMENT=1 \
				PORTA_IMPAIRMENT_PACKETS="$5" \
				PORTA_IMPAIRMENT_TIMEOUT_SECONDS="$6" \
				PORTA_IMPAIRMENT_PACING_MICROS="$7" \
				GODEBUG=http2xconnect=1 "$1" \
					-test.run "^TestTransportImpairment$" \
					-test.v \
					-test.count "$8"
			' -- "$test_binary" "$rtt" "$loss" "$rate" "$packets" "$timeout" "$pacing" "$count"
		done
	done
done
