#!/usr/bin/env bash
# End-to-end cascade relay test using network namespaces and real binaries.
#
#   client -> gateway 1 (relay) -> gateway 2 (relay) -> gateway 3 (exit) -> web
#
#   peer   -> gateway 1 (client-to-client enabled)
#
# Every gateway keeps the default 10.66.0.0/24 pool. The web server reports
# the source address it sees, which must be the exit gateway's address. The
# two clients of gateway 1 must reach each other. The test then stops the
# exit gateway, checks that relayed traffic fails closed, restarts it, and
# checks that the relays recover without intervention.
#
# Usage: sudo [PORTA_CASCADE_TRANSPORT=auto|h3|h2] scripts/test-cascade.sh \
#          [path-to-porta-server] [path-to-porta-client]
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "run with sudo" >&2; exit 2; }
repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
server_binary=$(realpath "${1:-$repository_root/rust/target/debug/porta-server}")
client_binary=$(realpath "${2:-$repository_root/rust/target/debug/porta-client}")
for binary in "$server_binary" "$client_binary"; do
  [[ -x $binary ]] || { echo "missing executable: $binary (build the workspace first)" >&2; exit 2; }
done
for command in curl ip nft openssl python3; do
  command -v "$command" >/dev/null || { echo "missing required command: $command" >&2; exit 2; }
done

gateways=3
transport=${PORTA_CASCADE_TRANSPORT:-auto}
[[ $transport =~ ^(auto|h3|h2)$ ]] || { echo "invalid PORTA_CASCADE_TRANSPORT" >&2; exit 2; }
port=8443
suffix=$$
work=$(mktemp -d /tmp/porta-cascade.XXXXXX)
chmod 0700 "$work"
pids=()
client_pids=()

ns() { printf 'pc%s-%s' "$suffix" "$1"; }
in_ns() { local name=$1; shift; ip netns exec "$(ns "$name")" "$@"; }
link_address() { printf '172.31.%s.%s' "$1" "$2"; }

cleanup() {
  local status=$?
  trap - EXIT
  for pid in "${client_pids[@]}"; do
    kill -INT "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  done
  for pid in "${pids[@]}"; do
    [[ -n $pid ]] && kill "$pid" 2>/dev/null || true
  done
  for pid in "${pids[@]}"; do
    [[ -n $pid ]] && wait "$pid" 2>/dev/null || true
  done
  for node in client peer $(seq 1 "$gateways") web; do
    ip netns delete "$(ns "$node")" 2>/dev/null || true
    rm -rf "/etc/netns/$(ns "$node")"
  done
  if [[ $status -ne 0 ]]; then
    echo "cascade test failed; logs:" >&2
    for log in "$work"/*.log; do
      [[ -f $log ]] || continue
      echo "==> $log" >&2
      tail -n 40 "$log" >&2
    done
  fi
  rm -rf "$work"
  exit "$status"
}
trap cleanup EXIT

# Nodes in a line: client(0), gateways 1..N, web(N+1). Link k joins node k
# ("east") to node k+1 ("west") on 172.31.k.0/30.
mapfile -t hops < <(seq 1 "$gateways")
nodes=(client "${hops[@]}" web)
for node in "${nodes[@]}"; do
  ip netns add "$(ns "$node")"
  in_ns "$node" ip link set lo up
done
for ((k = 0; k <= gateways; k++)); do
  left=${nodes[$k]}
  right=${nodes[$((k + 1))]}
  ip link add east netns "$(ns "$left")" type veth peer name west netns "$(ns "$right")"
  in_ns "$left" ip address add "$(link_address "$k" 1)/30" dev east
  in_ns "$right" ip address add "$(link_address "$k" 2)/30" dev west
  in_ns "$left" ip link set east up
  in_ns "$right" ip link set west up
  in_ns "$left" ip route add default via "$(link_address "$k" 2)"
done
# A second client of gateway 1 on its own link, 172.31.100.0/30.
ip netns add "$(ns peer)"
in_ns peer ip link set lo up
ip link add east netns "$(ns peer)" type veth peer name peer netns "$(ns 1)"
in_ns peer ip address add 172.31.100.1/30 dev east
in_ns 1 ip address add 172.31.100.2/30 dev peer
in_ns peer ip link set east up
in_ns 1 ip link set peer up
in_ns peer ip route add default via 172.31.100.2

web_address=$(link_address "$gateways" 2)
exit_address=$(link_address "$gateways" 1)
cat >"$work/web.py" <<'PY'
import http.server

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/bulk":
            body = bytes(range(256)) * (64 * 1024)
        else:
            body = self.client_address[0].encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass

http.server.ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
PY
ip netns exec "$(ns web)" python3 "$work/web.py" >"$work/web.log" 2>&1 &
pids[0]=$!
# A fake cloud metadata service beyond the exit; clients must never reach it.
in_ns web ip address add 169.254.169.254/32 dev west
# A service on the entry gateway host that clients must not reach.
ip netns exec "$(ns 1)" python3 -m http.server --bind 0.0.0.0 8081 >"$work/host-service.log" 2>&1 &
pids[100]=$!

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=Porta cascade test CA" \
  -keyout "$work/ca.key" -out "$work/ca.pem" >/dev/null 2>&1
for gateway in $(seq 1 "$gateways"); do
  directory=$work/gateway-$gateway
  install -d -m 0700 "$directory"
  public=$(link_address "$((gateway - 1))" 2)
  openssl req -newkey rsa:2048 -nodes -subj "/CN=$public" \
    -keyout "$directory/server.key" -out "$directory/server.csr" >/dev/null 2>&1
  openssl x509 -req -in "$directory/server.csr" -CA "$work/ca.pem" -CAkey "$work/ca.key" \
    -CAcreateserial -days 1 -extfile <(printf 'subjectAltName=IP:%s\n' "$public") \
    -out "$directory/server.crt" >/dev/null 2>&1
  openssl rand -hex 24 >"$directory/token"
done

start_gateway() {
  local gateway=$1
  local directory=$work/gateway-$gateway
  local arguments=(
    --listen ":$port" --admin-listen 127.0.0.1:9090
    --tls-cert "$directory/server.crt" --tls-key "$directory/server.key"
    --client-registry "$directory/clients.json" --lease-state "$directory/leases.json"
    --interface porta0 --egress-interface east --pool 10.66.0.0/24 --dns "$web_address"
  )
  local upstream_token=
  local upstream_options=()
  if ((gateway == 1)); then
    arguments+=(--client-to-client)
  fi
  if ((gateway < gateways)); then
    arguments+=(
      --upstream "https://$(link_address "$gateway" 2):$port"
      --upstream-ca "$work/ca.pem"
      --upstream-transport "$transport"
      --upstream-identity "$directory/upstream-identity.json"
    )
    upstream_token=$(<"$work/gateway-$((gateway + 1))/token")
    upstream_options=(--upstream-interface porta-up0)
  fi
  ip netns exec "$(ns "$gateway")" env \
    PORTA_TOKEN="$(<"$directory/token")" PORTA_ADMIN_TOKEN=admin-token-0123456789abcdef \
    PORTA_UPSTREAM_TOKEN="$upstream_token" \
    "$server_binary" "${arguments[@]}" >>"$work/gateway-$gateway.log" 2>&1 &
  pids[$gateway]=$!
  for _ in $(seq 1 100); do
    in_ns "$gateway" ip link show dev porta0 >/dev/null 2>&1 && break
    sleep 0.1
  done
  in_ns "$gateway" env PORTA_RUNTIME_DIRECTORY="$directory/runtime" \
    "$repository_root/scripts/server-up.sh" porta0 10.66.0.1/24 10.66.0.0/24 east "$port" \
    "${upstream_options[@]}" >>"$work/gateway-$gateway.log" 2>&1
}

stop_gateway() {
  local gateway=$1
  kill "${pids[$gateway]}"
  wait "${pids[$gateway]}" 2>/dev/null || true
  pids[$gateway]=
  in_ns "$gateway" env PORTA_RUNTIME_DIRECTORY="$work/gateway-$gateway/runtime" \
    "$repository_root/scripts/server-down.sh" porta0 east >>"$work/gateway-$gateway.log" 2>&1
}

# Calls a gateway's loopback admin API (default: the entry gateway).
admin_api() {
  local gateway=1
  if [[ ${1:-} =~ ^[0-9]+$ ]]; then gateway=$1; shift; fi
  in_ns "$gateway" curl -fsS --max-time 10 -H "Authorization: Bearer admin-token-0123456789abcdef" \
    -H "Content-Type: application/json" "$@"
}

wait_ready() {
  local gateway=$1
  for _ in $(seq 1 60); do
    if in_ns "$gateway" curl -fsS --max-time 5 http://127.0.0.1:9090/readyz >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  in_ns "$gateway" curl -sS --max-time 5 http://127.0.0.1:9090/readyz >&2 || true
  echo "nftables state of gateway $gateway:" >&2
  in_ns "$gateway" nft -j list table inet porta_guard >&2 || true
  echo "gateway $gateway did not become ready" >&2
  return 1
}

# Start from the exit so each relay can connect to its next hop.
for ((gateway = gateways; gateway >= 1; gateway--)); do
  start_gateway "$gateway"
  wait_ready "$gateway"
done
echo "all $gateways gateways are ready"

# Clients use automatic networking; fake only systemd-resolved's CLI.
install -d "$work/bin"
cat >"$work/bin/resolvectl" <<'EOF'
#!/usr/bin/env bash
case "${1:-}" in
  status|revert|default-route) exit 0 ;;
  dns|domain) [[ $# == 2 ]] && printf 'Link 2 (%s):\n' "$2"; exit 0 ;;
  *) exit 2 ;;
esac
EOF
chmod 0755 "$work/bin/resolvectl"

# Starts a client of gateway 1 and sets $lease once it is connected.
start_client() {
  local node=$1
  local identity=${2:-identity}
  install -d "/etc/netns/$(ns "$node")"
  printf 'nameserver 127.0.0.53\n' >"/etc/netns/$(ns "$node")/resolv.conf"
  install -d -m 0700 "$work/$node"
  # Truncate first: the background redirection may happen after the wait
  # loop below has already read a previous run's log.
  : >"$work/$node.log"
  ip netns exec "$(ns "$node")" env PORTA_TOKEN="$(<"$work/gateway-1/token")" PATH="$work/bin:$PATH" \
    "$client_binary" \
    --server "https://$(link_address 0 2):$port" --ca "$work/ca.pem" \
    --identity "$work/$node/$identity.json" --network-state "$work/$node/network-state.json" \
    --interface porta-ci0 --transport "$transport" >"$work/$node.log" 2>&1 &
  client_pids+=($!)
  local pid=$!
  for _ in $(seq 1 60); do
    if grep -qs "connected address=" "$work/$node.log"; then
      lease=$(sed -n 's/.*connected address=\([0-9.]*\).*/\1/p;T;q' "$work/$node.log")
      return 0
    fi
    kill -0 "$pid" 2>/dev/null || { echo "$node client exited" >&2; return 1; }
    sleep 1
  done
  echo "$node client did not connect" >&2
  return 1
}
start_client client
client_lease=$lease
start_client peer
peer_lease=$lease
echo "clients connected as $client_lease and $peer_lease"
in_ns client ping -n -c 2 -W 5 "$peer_lease" >/dev/null
in_ns peer ping -n -c 2 -W 5 "$client_lease" >/dev/null
echo "clients of gateway 1 reach each other (client-to-client)"
in_ns client ping -n -c 1 -W 5 10.66.0.1 >/dev/null
if in_ns client curl -fsS --max-time 3 http://10.66.0.1:8081/ >/dev/null 2>&1; then
  echo "client reached a host service on its gateway" >&2
  exit 1
fi
if in_ns client curl -fsS --max-time 3 http://169.254.169.254:8080/ >/dev/null 2>&1; then
  echo "client reached link-local instance metadata through the chain" >&2
  exit 1
fi
echo "clients can ping the gateway but not reach its host services or instance metadata"

# Device enrollment controls: with approval required, a new device key waits
# until an administrator approves it.
peer_pid=${client_pids[1]}
kill -INT "$peer_pid"; wait "$peer_pid" 2>/dev/null || true
gateway1_account=$(admin_api http://127.0.0.1:9090/api/clients |
  python3 -c 'import json, sys; print(json.load(sys.stdin)["clients"][0]["id"])')
admin_api -X PUT --data '{"policy":"approval"}' \
  "http://127.0.0.1:9090/api/clients/$gateway1_account/enrollment" >/dev/null
if start_client peer replacement 2>/dev/null; then
  echo "an unapproved device connected" >&2
  exit 1
fi
grep -q "waiting for administrator approval" "$work/peer.log" || {
  echo "the unapproved device did not report that it awaits approval" >&2
  exit 1
}
in_ns peer env PATH="$work/bin:$PATH" "$client_binary" --cleanup-network \
  --network-state "$work/peer/network-state.json" >/dev/null 2>&1 || true
pending_device=$(admin_api http://127.0.0.1:9090/api/clients | python3 -c '
import json, sys
devices = json.load(sys.stdin)["clients"][0]["devices"]
print(next(device["id"] for device in devices if device["status"] == "pending"))')
admin_api -X POST "http://127.0.0.1:9090/api/clients/$gateway1_account/devices/$pending_device/approve" >/dev/null
start_client peer replacement
in_ns peer ping -n -c 1 -W 5 "$client_lease" >/dev/null
admin_api -X PUT --data '{"policy":"open"}' \
  "http://127.0.0.1:9090/api/clients/$gateway1_account/enrollment" >/dev/null
echo "new devices wait for approval and connect once approved"


seen=$(in_ns client curl -fsS --max-time 10 "http://$web_address:8080/")
[[ $seen == "$exit_address" ]] || {
  echo "web server saw $seen, want exit gateway $exit_address" >&2
  exit 1
}
echo "traffic exits through gateway $gateways ($seen)"
bulk=$(in_ns client curl -fsS --max-time 60 -o /dev/null -w '%{size_download} %{speed_download}' \
  "http://$web_address:8080/bulk")
[[ ${bulk%% *} == 16777216 ]] || { echo "bulk transfer was incomplete: $bulk" >&2; exit 1; }
echo "16 MiB bulk transfer completed through the chain (${bulk#* } bytes/s)"
mtu=$(in_ns client cat /sys/class/net/porta-ci0/mtu)
in_ns client ping -n -c 2 -W 5 -M "do" -s $((mtu - 28)) "$web_address" >/dev/null
echo "full-size DF ping crosses the chain (client MTU $mtu)"
for gateway in $(seq 1 $((gateways - 1))); do
  in_ns "$gateway" curl -fsS --max-time 5 http://127.0.0.1:9090/readyz | grep -q '"upstream_tunnel"'
  for direction in tx rx; do
    packets=$(in_ns "$gateway" cat "/sys/class/net/porta-up0/statistics/${direction}_packets")
    ((packets > 0)) || {
      echo "relay $gateway carried no $direction packets through porta-up0" >&2
      exit 1
    }
  done
done
echo "every relay carried the traffic through its upstream tunnel"
admin_api http://127.0.0.1:9090/api/gateway | python3 -c '
import json, sys
upstream = json.load(sys.stdin)["upstream"]
assert upstream["connected"] and upstream["address"], upstream
' || { echo "entry gateway does not report its connected next hop" >&2; exit 1; }
echo "the admin API reports each relay's next-hop status"

stop_gateway "$gateways"
if in_ns client curl -fsS --max-time 5 "http://$web_address:8080/" >/dev/null 2>&1; then
  echo "relayed traffic still reached the web server with the exit gateway down" >&2
  exit 1
fi
route=$(in_ns "$((gateways - 1))" ip -4 route get "$web_address" from 10.66.0.2 iif porta0)
[[ $route == *"dev porta-up0"* ]] || {
  echo "relay would bypass its next hop: $route" >&2
  exit 1
}
next_hop_down=false
for _ in $(seq 1 30); do
  if admin_api "$((gateways - 1))" http://127.0.0.1:9090/api/gateway | python3 -c '
import json, sys
upstream = json.load(sys.stdin)["upstream"]
sys.exit(0 if not upstream["connected"] and upstream.get("error") else 1)
'; then
    next_hop_down=true
    break
  fi
  sleep 1
done
$next_hop_down || { echo "relay does not report its unavailable next hop" >&2; exit 1; }
echo "relayed traffic fails closed while the exit gateway is down"

start_gateway "$gateways"
wait_ready "$gateways"
for _ in $(seq 1 60); do
  seen=$(in_ns client curl -fsS --max-time 5 "http://$web_address:8080/" 2>/dev/null || true)
  [[ $seen == "$exit_address" ]] && break
  sleep 1
done
[[ $seen == "$exit_address" ]] || { echo "relays did not recover after the exit restarted" >&2; exit 1; }
echo "relays reconnected automatically after the exit gateway restarted"

# Account limits on the entry gateway, through its loopback admin API.
account_id=$(admin_api http://127.0.0.1:9090/api/clients |
  python3 -c 'import json, sys; print(json.load(sys.stdin)["clients"][0]["id"])')
admin_api -X PUT --data '{"expires_at":null,"monthly_quota_bytes":null,"rate_limit_kbps":8000}' \
  "http://127.0.0.1:9090/api/clients/$account_id/limits" >/dev/null
sleep 6 # one enforcement interval applies the rate limit to live sessions
# Reconnecting delivers the new limits to the client with its tunnel.
admin_api -X POST "http://127.0.0.1:9090/api/clients/$account_id/disconnect" >/dev/null
for _ in $(seq 1 30); do
  grep -q "rate-limit=8000kbit/s" "$work/client.log" && break
  sleep 1
done
grep -q "rate-limit=8000kbit/s" "$work/client.log" || {
  echo "client did not receive its account limits on reconnect" >&2
  exit 1
}
echo "reconnecting clients receive their account limits"
bulk=$(in_ns client curl -fsS --max-time 90 -o /dev/null -w '%{size_download} %{speed_download}' \
  "http://$web_address:8080/bulk")
[[ ${bulk%% *} == 16777216 ]] || { echo "rate-limited transfer was incomplete: $bulk" >&2; exit 1; }
speed=${bulk#* }
# 8 Mbit/s is 1 MB/s; allow the initial burst and measurement noise.
(( ${speed%.*} < 1300000 )) || { echo "8 Mbit/s limit not enforced: $speed bytes/s" >&2; exit 1; }
echo "8 Mbit/s account limit holds bulk transfer to $speed bytes/s"

admin_api -X PUT --data '{"expires_at":"2000-01-01T00:00:00Z","monthly_quota_bytes":null,"rate_limit_kbps":null}' \
  "http://127.0.0.1:9090/api/clients/$account_id/limits" >/dev/null
for _ in $(seq 1 30); do
  grep -q "account has expired" "$work/client.log" && break
  sleep 1
done
grep -q "account has expired" "$work/client.log" || {
  echo "client did not report the expired account" >&2
  exit 1
}
if in_ns client curl -fsS --max-time 5 "http://$web_address:8080/" >/dev/null 2>&1; then
  echo "expired account still reached the web server" >&2
  exit 1
fi
echo "expiring the account ends its live tunnels and the client reports why"
echo "cascade relay end-to-end test passed ($transport)"
