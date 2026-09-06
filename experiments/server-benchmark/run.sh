#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
work=${PORTA_RUST_BENCH_WORK:-"$root/.rust-benchmark"}
results=${PORTA_RUST_BENCH_RESULTS:-"$work/results.jsonl"}
repeats=${PORTA_RUST_BENCH_REPEATS:-5}
duration=${PORTA_RUST_BENCH_DURATION:-6s}
warmup=${PORTA_RUST_BENCH_WARMUP:-2s}
clients=${PORTA_RUST_BENCH_CLIENTS:-"1 16 64"}
server_cpus=${PORTA_RUST_BENCH_SERVER_CPUS:-"0,1"}
client_cpus=${PORTA_RUST_BENCH_CLIENT_CPUS:-"2,3"}
transport=${PORTA_RUST_BENCH_TRANSPORT:-h2}
server_threads=${PORTA_RUST_BENCH_SERVER_THREADS:-2}
client_threads=${PORTA_RUST_BENCH_CLIENT_THREADS:-2}
if [[ -n ${PORTA_RUST_BENCH_IMPLEMENTATIONS:-} ]]; then
	implementation_list=$PORTA_RUST_BENCH_IMPLEMENTATIONS
elif [[ $transport == h3 ]]; then
	implementation_list="go-direct rust-direct"
else
	implementation_list="go-direct rust-direct go-porta"
fi
inflight=${PORTA_RUST_BENCH_INFLIGHT:-1}
payload=${PORTA_RUST_BENCH_PAYLOAD:-1200}

mkdir -p "$work/bin" "$work/cargo-target" "$(dirname "$results")"
rm -f "$results"

cd "$root"
cargo=${CARGO:-cargo}
if [[ -x $HOME/.cargo/bin/cargo ]]; then
	cargo=${CARGO:-"$HOME/.cargo/bin/cargo"}
fi
go build -trimpath -o "$work/bin/go-server" ./experiments/server-benchmark/go-server
go build -trimpath -o "$work/bin/loadgen" ./experiments/server-benchmark/loadgen
CARGO_TARGET_DIR="$work/cargo-target" "$cargo" build --release \
	--manifest-path experiments/server-benchmark/rust-server/Cargo.toml
cp "$work/cargo-target/release/porta-rust-relay" "$work/bin/rust-server"
cp "$work/cargo-target/release/h3" "$work/bin/rust-h3-server"

certificate="$work/server.crt"
private_key="$work/server.key"
if [[ ! -s $certificate || ! -s $private_key ]]; then
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -sha256 \
		-days 1 -subj /CN=127.0.0.1 -addext subjectAltName=IP:127.0.0.1 \
		-keyout "$private_key" -out "$certificate" >/dev/null 2>&1
	chmod 0600 "$private_key"
fi

read -r -a client_counts <<<"$clients"
read -r -a implementations <<<"$implementation_list"
port=18443

cleanup_server() {
	if [[ -n ${server_pid:-} ]] && kill -0 "$server_pid" 2>/dev/null; then
		kill "$server_pid"
		wait "$server_pid" || true
	fi
}
trap cleanup_server EXIT

for client_count in "${client_counts[@]}"; do
	for ((repeat = 1; repeat <= repeats; repeat++)); do
		offset=$(( (repeat - 1) % ${#implementations[@]} ))
		for ((position = 0; position < ${#implementations[@]}; position++)); do
			implementation=${implementations[$(( (position + offset) % ${#implementations[@]} ))]}
			log="$work/${implementation}-${client_count}-${repeat}.log"
			case "$implementation" in
				go-direct)
					command=("$work/bin/go-server" --listen "127.0.0.1:$port" --cert "$certificate" --key "$private_key" --mode direct --transport "$transport")
					;;
				go-porta)
					command=("$work/bin/go-server" --listen "127.0.0.1:$port" --cert "$certificate" --key "$private_key" --mode porta --transport "$transport")
					;;
				rust-direct)
					if [[ $transport == h3 ]]; then
						command=("$work/bin/rust-h3-server" --listen "127.0.0.1:$port" --cert "$certificate" --key "$private_key")
					else
						command=("$work/bin/rust-server" --listen "127.0.0.1:$port" --cert "$certificate" --key "$private_key")
					fi
					;;
				*)
					echo "unknown implementation: $implementation" >&2
					exit 2
					;;
			esac
			taskset -c "$server_cpus" env GOMAXPROCS="$server_threads" \
				TOKIO_WORKER_THREADS="$server_threads" "${command[@]}" >"$log" 2>&1 &
			server_pid=$!
			for _ in $(seq 1 100); do
				grep -q '^LISTEN ' "$log" 2>/dev/null && break
				kill -0 "$server_pid" 2>/dev/null || {
					cat "$log" >&2
					exit 1
				}
				sleep 0.05
			done
			grep -q '^LISTEN ' "$log" || {
				echo "$implementation did not become ready" >&2
				exit 1
			}

			server_start_ticks=$(awk '{print $14+$15}' "/proc/$server_pid/stat")
			server_wall_start=$(date +%s%N)
			load_result=$(timeout --signal=TERM --kill-after=5s 90s \
				taskset -c "$client_cpus" env GOMAXPROCS="$client_threads" "$work/bin/loadgen" \
				-url "https://127.0.0.1:$port" -clients "$client_count" \
				-duration "$duration" -warmup "$warmup" -transport "$transport" \
				-inflight "$inflight" -payload "$payload")
			server_wall_end=$(date +%s%N)
			server_end_ticks=$(awk '{print $14+$15}' "/proc/$server_pid/stat")
			server_rss=$(awk '/^VmHWM:/ {print $2}' "/proc/$server_pid/status")
			kill "$server_pid"
			wait "$server_pid" || true
			server_pid=
			clock_ticks=$(getconf CLK_TCK)
			python3 - "$load_result" "$implementation" "$repeat" \
				"$server_start_ticks" "$server_end_ticks" "$clock_ticks" \
				"$server_wall_start" "$server_wall_end" "$server_rss" \
				"$transport" "$server_cpus" "$client_cpus" "$server_threads" "$client_threads" >>"$results" <<'PY'
import json
import sys
row = json.loads(sys.argv[1])
row["implementation"] = sys.argv[2]
row["repeat"] = int(sys.argv[3])
used_ticks = int(sys.argv[5]) - int(sys.argv[4])
elapsed = (int(sys.argv[8]) - int(sys.argv[7])) / 1e9
row["server_cpu_cores"] = used_ticks / int(sys.argv[6]) / elapsed
row["server_max_rss_kib"] = int(sys.argv[9])
row["transport"] = sys.argv[10]
row["server_cpus"] = sys.argv[11]
row["client_cpus"] = sys.argv[12]
row["server_threads"] = int(sys.argv[13])
row["client_threads"] = int(sys.argv[14])
print(json.dumps(row, sort_keys=True))
PY
			printf '%s clients=%s repeat=%s complete\n' "$implementation" "$client_count" "$repeat"
		done
	done
done

python3 experiments/server-benchmark/analyze.py "$results" | tee "$work/summary.md"
