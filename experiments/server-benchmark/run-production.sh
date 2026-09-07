#!/usr/bin/env bash
set -euo pipefail

if [[ ${1:-} == --inside ]]; then
	root=$2
	work=$3
	repeats=$4
	duration=$5
	warmup=$6
	clients=$7
	payload=$8
	server_cpus=$9
	client_cpus=${10}
	server_threads=${11}
	client_threads=${12}
	go_server=$work/bin/porta-go-server
	rust_server=$work/bin/porta-rust-server
	loadgen=$work/bin/loadgen
	admin_token=admin-token-0123456789abcdef
	token=benchmark-token-1234567890

	ip link set lo up
	ip addr add 1.1.1.1/32 dev lo
	nft add table ip porta_benchmark_nat
	nft 'add chain ip porta_benchmark_nat prerouting { type nat hook prerouting priority dstnat; policy accept; }'
	nft add rule ip porta_benchmark_nat prerouting \
		iifname porta0 ip daddr 1.1.1.1 udp dport 1-65535 dnat to 1.1.1.1:443
	python3 -c 'import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 << 20)
s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 << 20)
s.bind(("1.1.1.1", 443))
while True:
    data, peer = s.recvfrom(65535)
    s.sendto(data, peer)' &
	echo_pid=$!
	server_pid=
	cleanup() {
		if [[ -n $server_pid ]] && kill -0 "$server_pid" 2>/dev/null; then
			kill "$server_pid"
			wait "$server_pid" || true
		fi
		if kill -0 "$echo_pid" 2>/dev/null; then
			kill "$echo_pid"
			wait "$echo_pid" || true
		fi
	}
	trap cleanup EXIT

	printf 'implementation\ttransport\tclients\trepeat\tops_sec\tp95_us\tcpu_cores\tmax_rss_kib\n' \
		>"$work/results.tsv"
	: >"$work/results.jsonl"
	read -r -a client_counts <<<"$clients"
	for client_count in "${client_counts[@]}"; do
		for ((repeat = 1; repeat <= repeats; repeat++)); do
			if ((repeat % 2 == 1)); then
				implementations=(go rust)
			else
				implementations=(rust go)
			fi
			for implementation in "${implementations[@]}"; do
				for transport in h2 h3; do
					rm -f "$work/clients.json" "$work/leases.json" "$work/usage.json" \
						"$work/current.json" "$work/current.log"
					if [[ $implementation == go ]]; then
						binary=$go_server
					else
						binary=$rust_server
					fi
					taskset -c "$server_cpus" env \
						GOMAXPROCS="$server_threads" \
						TOKIO_WORKER_THREADS="$server_threads" \
						PORTA_ADMIN_TOKEN="$admin_token" \
						"$binary" \
						--listen 127.0.0.1:18443 \
						--tls-cert "$work/server.crt" \
						--tls-key "$work/server.key" \
						--admin-listen 127.0.0.1:19090 \
						--client-registry "$work/clients.json" \
						--lease-state "$work/leases.json" \
						--usage-state "$work/usage.json" \
						--token "$token" \
						--interface porta0 \
						--pool 10.66.0.0/24 \
						--dns 1.1.1.1 \
						--auto-mtu=false \
						--readiness-require-nat=false \
						--disable-forward-proxy >"$work/current.log" 2>&1 &
					server_pid=$!
					for _ in $(seq 1 200); do
						ip link show porta0 >/dev/null 2>&1 && break
						kill -0 "$server_pid"
						sleep 0.025
					done
					ip addr add 10.66.0.1/24 dev porta0
					ip link set porta0 mtu 1400 up
					sysctl -q -w net.ipv4.conf.porta0.accept_local=1
					sysctl -q -w net.ipv4.conf.porta0.rp_filter=2
					for _ in $(seq 1 200); do
						curl --fail --silent http://127.0.0.1:19090/healthz >/dev/null 2>&1 && break
						kill -0 "$server_pid"
						sleep 0.025
					done
					client_id=$(curl --fail --silent \
						-H "Authorization: Bearer $admin_token" \
						http://127.0.0.1:19090/api/clients |
						python3 -c 'import json, sys; print(json.load(sys.stdin)["clients"][0]["id"])')
					curl --fail --silent -X PUT \
						-H "Authorization: Bearer $admin_token" \
						-H 'Content-Type: application/json' \
						--data '{"name":"Default client","max_devices":100,"enabled":true}' \
						"http://127.0.0.1:19090/api/clients/$client_id" >/dev/null

					start_ticks=$(awk '{print $14+$15}' "/proc/$server_pid/stat")
					wall_start=$(date +%s%N)
					taskset -c "$client_cpus" env GOMAXPROCS="$client_threads" \
						"$loadgen" \
						-url https://127.0.0.1:18443 \
						-clients "$client_count" \
						-duration "$duration" \
						-warmup "$warmup" \
						-transport "$transport" \
						-payload "$payload" >"$work/current.json"
					wall_end=$(date +%s%N)
					end_ticks=$(awk '{print $14+$15}' "/proc/$server_pid/stat")
					max_rss=$(awk '/^VmHWM:/ {print $2}' "/proc/$server_pid/status")
					kill "$server_pid"
					wait "$server_pid"
					server_pid=
					python3 - "$work/current.json" "$implementation" "$transport" \
						"$client_count" "$repeat" "$start_ticks" "$end_ticks" \
						"$wall_start" "$wall_end" "$max_rss" "$work/results.tsv" \
						"$work/results.jsonl" <<'PY'
import json
import sys

(path, implementation, transport, clients, repeat, start, end,
 wall_start, wall_end, rss, tsv, jsonl) = sys.argv[1:]
row = json.load(open(path))
elapsed = (int(wall_end) - int(wall_start)) / 1e9
row.update(
    implementation=implementation,
    transport=transport,
    clients=int(clients),
    repeat=int(repeat),
    server_cpu_cores=(int(end) - int(start)) / 100 / elapsed,
    server_max_rss_kib=int(rss),
)
with open(tsv, "a") as output:
    output.write(
        f"{implementation}\t{transport}\t{clients}\t{repeat}\t"
        f"{row['operations_per_second']:.3f}\t{row['latency_p95_us']:.3f}\t"
        f"{row['server_cpu_cores']:.4f}\t{rss}\n"
    )
with open(jsonl, "a") as output:
    output.write(json.dumps(row, sort_keys=True) + "\n")
print(
    f"{implementation} {transport} clients={clients} repeat={repeat}: "
    f"{row['operations_per_second']:.0f}/s "
    f"p95={row['latency_p95_us']:.1f}us "
    f"cpu={row['server_cpu_cores']:.2f} rss={rss}KiB"
)
PY
				done
			done
		done
	done
	kill "$echo_pid"
	wait "$echo_pid" || true
	trap - EXIT
	python3 "$root/experiments/server-benchmark/summarize-production.py" \
		"$work/results.jsonl" | tee "$work/summary.md"
	exit
fi

root=$(cd "$(dirname "$0")/../.." && pwd)
work=${PORTA_PRODUCTION_BENCH_WORK:-"$root/.production-rust-benchmark"}
repeats=${PORTA_PRODUCTION_BENCH_REPEATS:-3}
duration=${PORTA_PRODUCTION_BENCH_DURATION:-1s}
warmup=${PORTA_PRODUCTION_BENCH_WARMUP:-500ms}
clients=${PORTA_PRODUCTION_BENCH_CLIENTS:-"1 16"}
payload=${PORTA_PRODUCTION_BENCH_PAYLOAD:-1200}
server_cpus=${PORTA_PRODUCTION_BENCH_SERVER_CPUS:-"0,1"}
client_cpus=${PORTA_PRODUCTION_BENCH_CLIENT_CPUS:-"2,3"}
server_threads=${PORTA_PRODUCTION_BENCH_SERVER_THREADS:-2}
client_threads=${PORTA_PRODUCTION_BENCH_CLIENT_THREADS:-2}
cargo=${CARGO:-"$HOME/.cargo/bin/cargo"}

mkdir -p "$work/bin"
rm -f "$work/bin/porta-go-server" "$work/bin/porta-rust-server" "$work/bin/loadgen" \
	"$work/server.crt" "$work/server.key" "$work/results.tsv" \
	"$work/results.jsonl" "$work/summary.md"
cd "$root"
go build -trimpath -o "$work/bin/porta-go-server" ./cmd/porta-server
go build -trimpath -o "$work/bin/loadgen" ./experiments/server-benchmark/loadgen
"$cargo" build --manifest-path rust/porta-server/Cargo.toml --locked --release
cp rust/porta-server/target/release/porta-server "$work/bin/porta-rust-server"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -sha256 \
	-days 1 -subj /CN=127.0.0.1 -addext subjectAltName=IP:127.0.0.1 \
	-keyout "$work/server.key" -out "$work/server.crt" >/dev/null 2>&1
chmod 0600 "$work/server.key"

sudo -n unshare --net -- "$root/experiments/server-benchmark/run-production.sh" \
	--inside "$root" "$work" "$repeats" "$duration" "$warmup" "$clients" \
	"$payload" "$server_cpus" "$client_cpus" "$server_threads" "$client_threads"
if [[ -n ${SUDO_USER:-} ]]; then
	owner=$SUDO_USER
else
	owner=$(id -un)
fi
sudo -n chown "$owner" "$work/results.tsv" "$work/results.jsonl" "$work/summary.md"
