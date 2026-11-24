#!/usr/bin/env bash
# End-to-end test of multi-gateway profiles and account federation using
# network namespaces and real binaries.
#
#   client --(slow link)--> primary P --.
#      \                    ^ accounts    +--> web
#       `-----------------> replica R --'
#
# R mirrors P's accounts. The client lists both gateways; R answers faster,
# but the new device must enroll on P first, so the client fails over to P.
# Once R has mirrored the device, stopping P moves the client to R without
# intervention. Account changes are refused on R, and disabling the account
# on P ends the client's session on R.
#
# Usage: sudo [PORTA_FAILOVER_TRANSPORT=auto|h3|h2] scripts/test-gateway-failover.sh \
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

transport=${PORTA_FAILOVER_TRANSPORT:-auto}
[[ $transport =~ ^(auto|h3|h2)$ ]] || { echo "invalid PORTA_FAILOVER_TRANSPORT" >&2; exit 2; }
port=8443
suffix=$$
work=$(mktemp -d /tmp/porta-failover.XXXXXX)
chmod 0700 "$work"
pids=()
declare -A gateway_pids=()
client_pid=
admin_token=admin-token-0123456789abcdef
federation_token=federation-token-0123456789abcdefghij
primary=https://172.31.0.2:$port
replica=https://172.31.1.2:$port

ns() { printf 'pf%s-%s' "$suffix" "$1"; }
in_ns() { local name=$1; shift; ip netns exec "$(ns "$name")" "$@"; }

cleanup() {
  local status=$?
  trap - EXIT
  if [[ -n $client_pid ]]; then
    kill -INT "$client_pid" 2>/dev/null || true
    wait "$client_pid" 2>/dev/null || true
  fi
  for gateway in "${!gateway_pids[@]}"; do
    kill "${gateway_pids[$gateway]}" 2>/dev/null || true
    wait "${gateway_pids[$gateway]}" 2>/dev/null || true
  done
  for pid in "${pids[@]}"; do
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  done
  for node in client p r web; do
    ip netns delete "$(ns "$node")" 2>/dev/null || true
    rm -rf "/etc/netns/$(ns "$node")"
  done
  if [[ $status -ne 0 ]]; then
    echo "gateway failover test failed; logs:" >&2
    for log in "$work"/*.log; do
      [[ -f $log ]] || continue
      echo "==> $log" >&2
      grep -v "connected address=" "$log" | tail -n 30 >&2
    done
  fi
  rm -rf "$work"
  exit "$status"
}
trap cleanup EXIT

for node in client p r web; do
  ip netns add "$(ns "$node")"
  in_ns "$node" ip link set lo up
done
link() {
  local left=$1 left_name=$2 left_address=$3 right=$4 right_name=$5 right_address=$6
  ip link add "$left_name" netns "$(ns "$left")" type veth peer name "$right_name" netns "$(ns "$right")"
  in_ns "$left" ip address add "$left_address" dev "$left_name"
  in_ns "$right" ip address add "$right_address" dev "$right_name"
  in_ns "$left" ip link set dev "$left_name" up
  in_ns "$right" ip link set dev "$right_name" up
}
link client to-p 172.31.0.1/30 p west 172.31.0.2/30
link client to-r 172.31.1.1/30 r west 172.31.1.2/30
link p peer 172.31.2.1/30 r peer 172.31.2.2/30
link p east 172.31.9.1/30 web from-p 172.31.9.2/30
link r east 172.31.8.1/30 web from-r 172.31.8.2/30
in_ns client ip route add default via 172.31.0.2
in_ns p ip route add default via 172.31.9.2
in_ns r ip route add default via 172.31.8.2
# Make the primary the slower gateway when netem is available.
if in_ns client tc qdisc add dev to-p root netem delay 40ms 2>/dev/null; then
  slow_primary=true
else
  slow_primary=false
fi

cat >"$work/web.py" <<'PY'
import http.server

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
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
pids+=($!)
in_ns web ip address add 192.0.2.80/32 dev lo
in_ns p ip route add 192.0.2.80/32 via 172.31.9.2
in_ns r ip route add 192.0.2.80/32 via 172.31.8.2
web=192.0.2.80

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=Porta failover test CA" \
  -keyout "$work/ca.key" -out "$work/ca.pem" >/dev/null 2>&1
certificate() {
  local name=$1 addresses=$2
  openssl req -newkey rsa:2048 -nodes -subj "/CN=$name" \
    -keyout "$work/$name.key" -out "$work/$name.csr" >/dev/null 2>&1
  openssl x509 -req -in "$work/$name.csr" -CA "$work/ca.pem" -CAkey "$work/ca.key" \
    -CAcreateserial -days 1 -extfile <(printf 'subjectAltName=%s\n' "$addresses") \
    -out "$work/$name.crt" >/dev/null 2>&1
}
certificate p "IP:172.31.0.2,IP:172.31.2.1"
certificate r "IP:172.31.1.2"
openssl rand -hex 24 >"$work/token"

start_gateway() {
  local gateway=$1
  shift
  install -d -m 0700 "$work/$gateway"
  ip netns exec "$(ns "$gateway")" env \
    PORTA_TOKEN="$(<"$work/token")" PORTA_ADMIN_TOKEN="$admin_token" \
    PORTA_FEDERATION_TOKEN="$federation_token" \
    "$server_binary" --listen ":$port" --admin-listen 127.0.0.1:9090 \
    --tls-cert "$work/$gateway.crt" --tls-key "$work/$gateway.key" \
    --client-registry "$work/$gateway/clients.json" --lease-state "$work/$gateway/leases.json" \
    --interface porta0 --egress-interface east --pool 10.66.0.0/24 --dns 192.0.2.53 \
    "$@" >>"$work/$gateway.log" 2>&1 &
  gateway_pids[$gateway]=$!
  for _ in $(seq 1 100); do
    in_ns "$gateway" ip link show dev porta0 >/dev/null 2>&1 && break
    sleep 0.1
  done
  in_ns "$gateway" env PORTA_RUNTIME_DIRECTORY="$work/$gateway/runtime" \
    "$repository_root/scripts/server-up.sh" porta0 10.66.0.1/24 10.66.0.0/24 east "$port" \
    >>"$work/$gateway.log" 2>&1
  for _ in $(seq 1 60); do
    in_ns "$gateway" curl -fsS --max-time 5 http://127.0.0.1:9090/readyz >/dev/null 2>&1 && return 0
    sleep 1
  done
  echo "gateway $gateway did not become ready" >&2
  return 1
}
stop_gateway() {
  local gateway=$1
  kill "${gateway_pids[$gateway]}"
  wait "${gateway_pids[$gateway]}" 2>/dev/null || true
  unset "gateway_pids[$gateway]"
  in_ns "$gateway" env PORTA_RUNTIME_DIRECTORY="$work/$gateway/runtime" \
    "$repository_root/scripts/server-down.sh" porta0 east >>"$work/$gateway.log" 2>&1
}
admin_api() {
  local gateway=$1
  shift
  in_ns "$gateway" curl -fsS --max-time 10 -H "Authorization: Bearer $admin_token" \
    -H "Content-Type: application/json" "$@"
}
json() { python3 -c "import json, sys; print($1)"; }
# Waits until a Python expression over gateway R's client list holds.
wait_replica() {
  local expression=$1 what=$2
  for _ in $(seq 1 60); do
    if admin_api r http://127.0.0.1:9090/api/clients 2>/dev/null |
      python3 -c "import json, sys; clients = json.load(sys.stdin)['clients']; sys.exit(0 if ($expression) else 1)"; then
      return 0
    fi
    sleep 1
  done
  echo "the replica did not $what" >&2
  return 1
}

start_gateway p
start_gateway r --federation-primary "https://172.31.2.1:$port" --federation-ca "$work/ca.pem"
wait_replica "len(clients) == 1" "mirror the primary's account"
admin_api r http://127.0.0.1:9090/api/gateway | python3 -c '
import json, sys
federation = json.load(sys.stdin)["federation"]
assert federation["role"] == "replica" and federation["connected"], federation'
[[ $(admin_api p http://127.0.0.1:9090/api/gateway | json 'json.load(sys.stdin)["federation"]["role"]') == primary ]]
echo "the replica mirrors the primary's accounts"

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
install -d "/etc/netns/$(ns client)"
printf 'nameserver 127.0.0.53\n' >"/etc/netns/$(ns client)/resolv.conf"
install -d -m 0700 "$work/client"
ip netns exec "$(ns client)" env PORTA_TOKEN="$(<"$work/token")" PATH="$work/bin:$PATH" \
  "$client_binary" --server "$primary" --server "$replica" --ca "$work/ca.pem" \
  --identity "$work/client/identity.json" --network-state "$work/client/network-state.json" \
  --interface porta-ci0 --transport "$transport" >"$work/client.log" 2>&1 &
client_pid=$!

seen() { in_ns client curl -fsS --max-time 3 "http://$web:8080/" 2>/dev/null || true; }
expect_exit() {
  local want=$1 what=$2 observed=
  for _ in $(seq 1 90); do
    observed=$(seen)
    [[ $observed == "$want" ]] && return 0
    kill -0 "$client_pid" 2>/dev/null || { echo "client exited" >&2; exit 1; }
    sleep 1
  done
  echo "$what: web server saw '${observed}', want $want" >&2
  exit 1
}
expect_exit 172.31.9.1 "first connection"
if $slow_primary; then
  grep -q "gateway order: 172.31.1.2" "$work/client.log" || {
    echo "the client did not try the faster replica first" >&2
    exit 1
  }
  grep -q "enroll on the primary gateway" "$work/client.log" || {
    echo "the replica did not send the new device to the primary" >&2
    exit 1
  }
fi
echo "a new device fails over from the replica to the primary to enroll"

wait_replica "len(clients[0]['devices']) == 1" "mirror the enrolled device"
mirrored=$(admin_api r http://127.0.0.1:9090/api/clients | json 'json.load(sys.stdin)["clients"][0]["id"]')
[[ $(in_ns r curl -sS --max-time 10 -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $admin_token" \
  -H "Content-Type: application/json" -X PUT --data '{"name":"X","max_devices":1}' \
  "http://127.0.0.1:9090/api/clients/$mirrored") == 400 ]] || {
  echo "the replica accepted an account change" >&2
  exit 1
}
echo "accounts are read-only on the replica"

stop_gateway p
expect_exit 172.31.8.1 "after the primary stopped"
echo "the client failed over to the replica when the primary stopped"

start_gateway p
wait_replica "True" "come back"
account=$(admin_api p http://127.0.0.1:9090/api/clients | json 'json.load(sys.stdin)["clients"][0]["id"]')
admin_api p -X PUT --data '{"name":"Default client","max_devices":5,"enabled":false}' \
  "http://127.0.0.1:9090/api/clients/$account" >/dev/null
for _ in $(seq 1 60); do
  kill -0 "$client_pid" 2>/dev/null || break
  [[ -z $(seen) ]] && grep -q "401\|Unauthorized\|rejected" "$work/client.log" && break
  sleep 1
done
[[ -z $(seen) ]] || { echo "the disabled account still reaches the web through the replica" >&2; exit 1; }
echo "disabling the account on the primary ends its session on the replica"
echo "gateway failover test passed ($transport)"
