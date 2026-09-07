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
	transports=${13}
	auto_mtu=${14}
	inflight=${15}
	loadgen_specs=${16}
	attempts=${17}
	rust_server=$work/bin/porta-server
	admin_token=admin-token-0123456789abcdef
	token=benchmark-token-1234567890
	clock_ticks=$(getconf CLK_TCK)

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

	stop_server() {
		if [[ -n $server_pid ]] && kill -0 "$server_pid" 2>/dev/null; then
			kill "$server_pid"
			wait "$server_pid" || true
		fi
		server_pid=
	}

	cleanup() {
		stop_server
		if kill -0 "$echo_pid" 2>/dev/null; then
			kill "$echo_pid"
			wait "$echo_pid" || true
		fi
	}
	trap cleanup EXIT

	run_one() {
		local client_count=$1
		local repeat=$2
		local transport=$3
		local client_implementation=$4
		local loadgen=$5
		local ready=false

		rm -f "$work/clients.json" "$work/leases.json" "$work/usage.json" \
			"$work/current.json" "$work/current.log" "$work/client-usage.txt"
		taskset -c "$server_cpus" env \
			TOKIO_WORKER_THREADS="$server_threads" \
			PORTA_ADMIN_TOKEN="$admin_token" \
			"$rust_server" \
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
				--auto-mtu="$auto_mtu" \
				--readiness-require-nat=false \
				--disable-forward-proxy >"$work/current.log" 2>&1 &
		server_pid=$!
		for _ in $(seq 1 200); do
			if ip link show porta0 >/dev/null 2>&1; then
				ready=true
				break
			fi
			kill -0 "$server_pid"
			sleep 0.025
		done
		if [[ $ready != true ]]; then
			echo "Porta server did not create porta0" >&2
			return 1
		fi

		ip addr add 10.66.0.1/24 dev porta0
		ip link set porta0 mtu 1400 up
		sysctl -q -w net.ipv4.conf.porta0.accept_local=1
		sysctl -q -w net.ipv4.conf.porta0.rp_filter=2
		ready=false
		for _ in $(seq 1 200); do
			if curl --fail --silent http://127.0.0.1:19090/healthz >/dev/null 2>&1; then
				ready=true
				break
			fi
			kill -0 "$server_pid"
			sleep 0.025
		done
		if [[ $ready != true ]]; then
			echo "Porta server did not become ready" >&2
			return 1
		fi

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
		if ! /usr/bin/time -f '%U %S %M' -o "$work/client-usage.txt" \
			taskset -c "$client_cpus" env GOMAXPROCS="$client_threads" \
			"$loadgen" \
			-url https://127.0.0.1:18443 \
			-clients "$client_count" \
			-duration "$duration" \
			-warmup "$warmup" \
			-transport "$transport" \
			-require-auto-mtu="$auto_mtu" \
			-inflight "$inflight" \
			-payload "$payload" >"$work/current.json"; then
			return 1
		fi
		wall_end=$(date +%s%N)
		end_ticks=$(awk '{print $14+$15}' "/proc/$server_pid/stat")
		server_max_rss=$(awk '/^VmHWM:/ {print $2}' "/proc/$server_pid/status")
		read -r client_user_seconds client_system_seconds client_max_rss \
			<"$work/client-usage.txt"
		stop_server

		python3 - "$work/current.json" "$client_implementation" "$transport" \
			"$client_count" "$repeat" "$start_ticks" "$end_ticks" \
			"$clock_ticks" "$wall_start" "$wall_end" "$server_max_rss" \
			"$client_user_seconds" "$client_system_seconds" "$client_max_rss" \
			"$work/results.tsv" "$work/results.jsonl" <<'PY'
import json
import sys

(path, client_implementation, transport, clients, repeat, start, end,
 clock_ticks, wall_start, wall_end, server_rss, client_user, client_system,
 client_rss, tsv, jsonl) = sys.argv[1:]
row = json.load(open(path, encoding="utf-8"))
elapsed = (int(wall_end) - int(wall_start)) / 1e9
row.update(
    implementation="rust",
    server_implementation="rust",
    client_implementation=client_implementation,
    transport=transport,
    clients=int(clients),
    repeat=int(repeat),
    server_cpu_cores=(int(end) - int(start)) / int(clock_ticks) / elapsed,
    server_max_rss_kib=int(server_rss),
    client_cpu_cores=(float(client_user) + float(client_system)) / elapsed,
    client_max_rss_kib=int(client_rss),
)
with open(tsv, "a", encoding="utf-8") as output:
    output.write(
        f"{client_implementation}\t{transport}\t{clients}\t{repeat}\t"
        f"{row['operations_per_second']:.3f}\t{row['latency_p95_us']:.3f}\t"
        f"{row['server_cpu_cores']:.4f}\t{server_rss}\t"
        f"{row['client_cpu_cores']:.4f}\t{client_rss}\n"
    )
with open(jsonl, "a", encoding="utf-8") as output:
    output.write(json.dumps(row, sort_keys=True) + "\n")
print(
    f"{client_implementation} {transport} clients={clients} repeat={repeat}: "
    f"{row['operations_per_second']:.0f}/s "
    f"p95={row['latency_p95_us']:.1f}us "
    f"server_cpu={row['server_cpu_cores']:.2f} "
    f"client_cpu={row['client_cpu_cores']:.2f} "
    f"client_rss={client_rss}KiB"
)
PY
	}

	printf 'client_implementation\ttransport\tclients\trepeat\tops_sec\tp95_us\tserver_cpu_cores\tserver_max_rss_kib\tclient_cpu_cores\tclient_max_rss_kib\n' \
		>"$work/results.tsv"
	: >"$work/results.jsonl"
	read -r -a client_counts <<<"$clients"
	read -r -a transport_list <<<"$transports"
	read -r -a loadgen_list <<<"$loadgen_specs"
	for client_count in "${client_counts[@]}"; do
		for ((repeat = 1; repeat <= repeats; repeat++)); do
			for transport in "${transport_list[@]}"; do
				for loadgen_spec in "${loadgen_list[@]}"; do
					client_implementation=${loadgen_spec%%=*}
					loadgen=${loadgen_spec#*=}
					succeeded=false
					for ((attempt = 1; attempt <= attempts; attempt++)); do
						if run_one "$client_count" "$repeat" "$transport" \
							"$client_implementation" "$loadgen"; then
							succeeded=true
							break
						fi
						stop_server
						echo "$client_implementation $transport clients=$client_count repeat=$repeat attempt=$attempt failed; retrying" >&2
					done
					if [[ $succeeded != true ]]; then
						echo "$client_implementation $transport clients=$client_count repeat=$repeat failed after $attempts attempts" >&2
						exit 1
					fi
				done
			done
		done
	done

	kill "$echo_pid"
	wait "$echo_pid" || true
	trap - EXIT
	python3 "$root/experiments/server-benchmark/summarize.py" \
		"$work/results.jsonl" | tee "$work/summary.md"
	exit
fi

root=$(cd "$(dirname "$0")/../.." && pwd)
work=${PORTA_SERVER_BENCH_WORK:-"$root/.server-benchmark"}
repeats=${PORTA_SERVER_BENCH_REPEATS:-3}
duration=${PORTA_SERVER_BENCH_DURATION:-1s}
warmup=${PORTA_SERVER_BENCH_WARMUP:-500ms}
clients=${PORTA_SERVER_BENCH_CLIENTS:-"1 16"}
payload=${PORTA_SERVER_BENCH_PAYLOAD:-1200}
server_cpus=${PORTA_SERVER_BENCH_SERVER_CPUS:-"0,1"}
client_cpus=${PORTA_SERVER_BENCH_CLIENT_CPUS:-"2,3"}
server_threads=${PORTA_SERVER_BENCH_SERVER_THREADS:-2}
client_threads=${PORTA_SERVER_BENCH_CLIENT_THREADS:-2}
inflight=${PORTA_SERVER_BENCH_INFLIGHT:-1}
transports=${PORTA_SERVER_BENCH_TRANSPORTS:-"h2 h3"}
auto_mtu=${PORTA_SERVER_BENCH_AUTO_MTU:-false}
cargo=${CARGO:-"$HOME/.cargo/bin/cargo"}
loadgen_specs=${PORTA_SERVER_BENCH_LOADGENS:-}
attempts=${PORTA_SERVER_BENCH_ATTEMPTS:-3}

if [[ ${PORTA_BENCH_QUICK:-0} == 1 ]]; then
	repeats=${PORTA_SERVER_BENCH_REPEATS:-1}
	duration=${PORTA_SERVER_BENCH_DURATION:-500ms}
	warmup=${PORTA_SERVER_BENCH_WARMUP:-100ms}
	clients=${PORTA_SERVER_BENCH_CLIENTS:-1}
	transports=${PORTA_SERVER_BENCH_TRANSPORTS:-"h2 h3 auto"}
	auto_mtu=${PORTA_SERVER_BENCH_AUTO_MTU:-true}
fi

mkdir -p "$work/bin"
rm -f "$work/bin/porta-server" "$work/bin/porta-loadgen" \
	"$work/server.crt" "$work/server.key" "$work/results.tsv" \
	"$work/results.jsonl" "$work/summary.md"
cd "$root"
"$cargo" build --manifest-path rust/Cargo.toml --locked --release \
	--package porta-server-rust --package porta-loadgen
cp rust/target/release/porta-server "$work/bin/porta-server"
cp rust/target/release/porta-loadgen "$work/bin/porta-loadgen"

if [[ -z $loadgen_specs ]]; then
	if [[ -n ${PORTA_SERVER_BENCH_LOADGEN:-} ]]; then
		loadgen_specs="${PORTA_SERVER_BENCH_LOADGEN_IMPLEMENTATION:-custom}=${PORTA_SERVER_BENCH_LOADGEN}"
	else
		loadgen_specs="rust=$work/bin/porta-loadgen"
	fi
fi
normalized_loadgens=()
read -r -a requested_loadgens <<<"$loadgen_specs"
for specification in "${requested_loadgens[@]}"; do
	if [[ $specification != *=* ]]; then
		echo "invalid load generator specification: $specification" >&2
		exit 2
	fi
	implementation=${specification%%=*}
	loadgen=${specification#*=}
	if [[ ! $implementation =~ ^[A-Za-z0-9._-]+$ ]]; then
		echo "invalid load generator implementation label: $implementation" >&2
		exit 2
	fi
	loadgen=$(realpath "$loadgen")
	if [[ ! -x $loadgen ]]; then
		echo "load generator is not executable: $loadgen" >&2
		exit 2
	fi
	normalized_loadgens+=("$implementation=$loadgen")
done
loadgen_specs="${normalized_loadgens[*]}"
if [[ ! -x /usr/bin/time ]]; then
	echo "GNU time is required at /usr/bin/time" >&2
	exit 2
fi

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -sha256 \
	-days 1 -subj /CN=127.0.0.1 -addext subjectAltName=IP:127.0.0.1 \
	-keyout "$work/server.key" -out "$work/server.crt" >/dev/null 2>&1
chmod 0600 "$work/server.key"

sudo -n unshare --net -- "$root/experiments/server-benchmark/run.sh" \
	--inside "$root" "$work" "$repeats" "$duration" "$warmup" "$clients" \
	"$payload" "$server_cpus" "$client_cpus" "$server_threads" "$client_threads" \
	"$transports" "$auto_mtu" "$inflight" "$loadgen_specs" "$attempts"
if [[ -n ${SUDO_USER:-} ]]; then
	owner=$SUDO_USER
else
	owner=$(id -un)
fi
sudo -n chown "$owner" "$work/results.tsv" "$work/results.jsonl" "$work/summary.md"
