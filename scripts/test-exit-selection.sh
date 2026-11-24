#!/usr/bin/env bash
# End-to-end test of per-account exit selection using network namespaces
# and real binaries.
#
#   client -> relay R --(default upstream)--> exit X1 --.
#                     --(named exit "us")---> exit X2 ---+-> web
#                     --(local exit)--------------------'
#
# The web server reports the source address it sees, which identifies the
# exit. The test switches the account between the default, "us" and
# "local" exits, checks that a selected exit that is down fails closed
# instead of falling back to another path, and that stopping the relay
# removes its exit rules.
#
# Usage: sudo [PORTA_EXIT_TRANSPORT=auto|h3|h2] scripts/test-exit-selection.sh \
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

transport=${PORTA_EXIT_TRANSPORT:-auto}
[[ $transport =~ ^(auto|h3|h2)$ ]] || { echo "invalid PORTA_EXIT_TRANSPORT" >&2; exit 2; }
port=8443
suffix=$$
work=$(mktemp -d /tmp/porta-exit.XXXXXX)
chmod 0700 "$work"
pids=()
declare -A gateway_pids=()
client_pid=
admin_token=admin-token-0123456789abcdef
web_address=172.31.13.2

ns() { printf 'pe%s-%s' "$suffix" "$1"; }
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
  for node in client relay x1 x2 web; do
    ip netns delete "$(ns "$node")" 2>/dev/null || true
    rm -rf "/etc/netns/$(ns "$node")"
  done
  if [[ $status -ne 0 ]]; then
    echo "exit selection test failed; logs:" >&2
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

for node in client relay x1 x2 web; do
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
link client east 172.31.0.1/30 relay west 172.31.0.2/30
link relay x1 172.31.1.1/30 x1 west 172.31.1.2/30
link relay x2 172.31.2.1/30 x2 west 172.31.2.2/30
link relay east 172.31.13.1/30 web relay 172.31.13.2/30
link x1 east 172.31.11.1/30 web x1 172.31.11.2/30
link x2 east 172.31.12.1/30 web x2 172.31.12.2/30
in_ns client ip route add default via 172.31.0.2
in_ns relay ip route add default via 172.31.13.2
in_ns x1 ip route add default via 172.31.11.2
in_ns x2 ip route add default via 172.31.12.2

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

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=Porta exit test CA" \
  -keyout "$work/ca.key" -out "$work/ca.pem" >/dev/null 2>&1
certificate() {
  local name=$1 address=$2
  openssl req -newkey rsa:2048 -nodes -subj "/CN=$address" \
    -keyout "$work/$name.key" -out "$work/$name.csr" >/dev/null 2>&1
  openssl x509 -req -in "$work/$name.csr" -CA "$work/ca.pem" -CAkey "$work/ca.key" \
    -CAcreateserial -days 1 -extfile <(printf 'subjectAltName=IP:%s\n' "$address") \
    -out "$work/$name.crt" >/dev/null 2>&1
  openssl rand -hex 24 >"$work/$name.token"
}
certificate relay 172.31.0.2
certificate x1 172.31.1.2
certificate x2 172.31.2.2

# Starts gateway $1 (relay, x1 or x2) with daemon options after "--" and
# network helper options after the daemon's.
start_gateway() {
  local gateway=$1 extra=() helper=()
  shift
  while [[ $# -gt 0 && $1 != -- ]]; do extra+=("$1"); shift; done
  [[ $# -gt 0 ]] && shift
  helper=("$@")
  install -d -m 0700 "$work/$gateway"
  ip netns exec "$(ns "$gateway")" env \
    PORTA_TOKEN="$(<"$work/$gateway.token")" PORTA_ADMIN_TOKEN="$admin_token" \
    PORTA_UPSTREAM_TOKEN="$(<"$work/x1.token")" PORTA_EXIT_TOKEN_US="$(<"$work/x2.token")" \
    "$server_binary" --listen ":$port" --admin-listen 127.0.0.1:9090 \
    --tls-cert "$work/$gateway.crt" --tls-key "$work/$gateway.key" \
    --client-registry "$work/$gateway/clients.json" --lease-state "$work/$gateway/leases.json" \
    --interface porta0 --egress-interface east --pool 10.66.0.0/24 --dns "$web_address" \
    "${extra[@]}" >>"$work/$gateway.log" 2>&1 &
  gateway_pids[$gateway]=$!
  for _ in $(seq 1 100); do
    in_ns "$gateway" ip link show dev porta0 >/dev/null 2>&1 && break
    sleep 0.1
  done
  in_ns "$gateway" env PORTA_RUNTIME_DIRECTORY="$work/$gateway/runtime" \
    "$repository_root/scripts/server-up.sh" porta0 10.66.0.1/24 10.66.0.0/24 east "$port" \
    "${helper[@]}" >>"$work/$gateway.log" 2>&1
  for _ in $(seq 1 60); do
    in_ns "$gateway" curl -fsS --max-time 5 http://127.0.0.1:9090/readyz >/dev/null 2>&1 && return 0
    sleep 1
  done
  in_ns "$gateway" curl -sS --max-time 5 http://127.0.0.1:9090/readyz >&2 || true
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

start_gateway x1
start_gateway x2
start_gateway relay \
  --upstream https://172.31.1.2:$port --upstream-ca "$work/ca.pem" \
  --upstream-transport "$transport" --upstream-identity "$work/relay/upstream-identity.json" \
  --exit us=https://172.31.2.2:$port --local-exit -- \
  --upstream-interface porta-up0 --exit-interface porta-up1 --local-exit
echo "relay, default exit and named exit are ready"

admin_api() {
  in_ns relay curl -fsS --max-time 10 -H "Authorization: Bearer $admin_token" \
    -H "Content-Type: application/json" "$@"
}
in_ns relay curl -fsS --max-time 10 -H "Authorization: Bearer $admin_token" \
  http://127.0.0.1:9090/api/gateway | python3 -c '
import json, sys
status = json.load(sys.stdin)
assert status["exits"] == ["local", "us"], status
assert [upstream.get("name", "") for upstream in status["upstreams"]] == ["", "us"], status
assert all(upstream["connected"] for upstream in status["upstreams"]), status'
echo "the admin API reports both next hops and the selectable exits"

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
ip netns exec "$(ns client)" env PORTA_TOKEN="$(<"$work/relay.token")" PATH="$work/bin:$PATH" \
  "$client_binary" --server "https://172.31.0.2:$port" --ca "$work/ca.pem" \
  --identity "$work/client/identity.json" --network-state "$work/client/network-state.json" \
  --interface porta-ci0 --transport "$transport" >"$work/client.log" 2>&1 &
client_pid=$!
for _ in $(seq 1 60); do
  grep -qs "connected address=" "$work/client.log" && break
  kill -0 "$client_pid" 2>/dev/null || { echo "client exited" >&2; exit 1; }
  sleep 1
done

seen() { in_ns client curl -fsS --max-time 3 "http://$web_address:8080/" 2>/dev/null || true; }
# Waits while a policy change reconnects the client.
expect_exit() {
  local want=$1 what=$2 observed=
  for _ in $(seq 1 30); do
    observed=$(seen)
    [[ $observed == "$want" ]] && return 0
    sleep 1
  done
  echo "$what: web server saw '${observed}', want $want" >&2
  exit 1
}
account=$(admin_api http://127.0.0.1:9090/api/clients |
  python3 -c 'import json, sys; print(json.load(sys.stdin)["clients"][0]["id"])')
set_exit() {
  admin_api -X PUT --data "{\"exit\":$1}" "http://127.0.0.1:9090/api/clients/$account/access" >/dev/null
}
exit_rules() { in_ns relay ip -4 rule show priority 10065 | grep -c . || true; }

expect_exit 172.31.11.1 "default exit"
[[ $(exit_rules) == 0 ]] || { echo "the default exit installed a selection rule" >&2; exit 1; }
set_exit '"us"'
expect_exit 172.31.12.1 "named exit"
[[ $(exit_rules) == 1 ]] || { echo "expected one exit selection rule" >&2; exit 1; }
set_exit '"local"'
expect_exit 172.31.13.1 "local exit"
[[ $(exit_rules) == 1 ]] || { echo "a stale exit selection rule remained" >&2; exit 1; }
if admin_api -X PUT --data '{"exit":"elsewhere"}' \
  "http://127.0.0.1:9090/api/clients/$account/access" >/dev/null 2>&1; then
  echo "the gateway accepted an exit it does not offer" >&2
  exit 1
fi
echo "the account's traffic leaves through the selected exit"

set_exit '"us"'
expect_exit 172.31.12.1 "named exit before outage"
stop_gateway x2
sleep 3
leak=$(seen)
[[ -z $leak ]] || { echo "traffic for a down exit left through another path (seen as $leak)" >&2; exit 1; }
echo "a selected exit that is down fails closed"
set_exit null
expect_exit 172.31.11.1 "default exit after clearing the selection"
[[ $(exit_rules) == 0 ]] || { echo "clearing the exit left a selection rule" >&2; exit 1; }

set_exit '"local"'
expect_exit 172.31.13.1 "local exit before relay restart"
kill -INT "$client_pid"
wait "$client_pid" 2>/dev/null || true
client_pid=
stop_gateway relay
[[ $(exit_rules) == 0 ]] || { echo "stopping the relay left exit selection rules" >&2; exit 1; }
echo "stopping the relay removes its exit rules"
echo "exit selection test passed ($transport)"
