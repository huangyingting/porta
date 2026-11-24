#!/usr/bin/env bash
# End-to-end test of subnet routing and per-account access policy using
# network namespaces and real binaries.
#
#   client A (account alpha) --.
#                               gateway -- web (the exit's Internet)
#   client B (account beta) ---'
#      `-- lan: 10.30.0.5, behind B, with no route back to the client pool
#
# An administrator routes 10.30.0.0/24 to B's device and B runs with
# --subnet-router. The test checks that the accounts reach each other and
# the LAN only once they share an access group, that a deny list and an
# allow list are enforced, that LAN hosts see B's masqueraded address, and
# that B restores IPv4 forwarding when it disconnects.
#
# Usage: sudo [PORTA_SUBNET_TRANSPORT=auto|h3|h2] scripts/test-subnet-router.sh \
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

transport=${PORTA_SUBNET_TRANSPORT:-auto}
[[ $transport =~ ^(auto|h3|h2)$ ]] || { echo "invalid PORTA_SUBNET_TRANSPORT" >&2; exit 2; }
port=8443
suffix=$$
work=$(mktemp -d /tmp/porta-subnet.XXXXXX)
chmod 0700 "$work"
pids=()
gateway_pid=
declare -A client_pids=()
admin_token=admin-token-0123456789abcdef

ns() { printf 'pr%s-%s' "$suffix" "$1"; }
in_ns() { local name=$1; shift; ip netns exec "$(ns "$name")" "$@"; }

cleanup() {
  local status=$?
  trap - EXIT
  for pid in "${client_pids[@]}"; do
    kill -INT "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  done
  if [[ -n $gateway_pid ]]; then
    kill "$gateway_pid" 2>/dev/null || true
    wait "$gateway_pid" 2>/dev/null || true
  fi
  for pid in "${pids[@]}"; do
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  done
  for node in a b gateway web lan; do
    ip netns delete "$(ns "$node")" 2>/dev/null || true
    rm -rf "/etc/netns/$(ns "$node")"
  done
  if [[ $status -ne 0 ]]; then
    echo "subnet router test failed; logs:" >&2
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

for node in a b gateway web lan; do
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
link a east 172.31.0.1/30 gateway to-a 172.31.0.2/30
link b east 172.31.1.1/30 gateway to-b 172.31.1.2/30
link gateway east 172.31.9.1/30 web west 172.31.9.2/30
link b lan 10.30.0.1/24 lan west 10.30.0.5/24
in_ns a ip route add default via 172.31.0.2
in_ns b ip route add default via 172.31.1.2
in_ns gateway ip route add default via 172.31.9.2
# New namespaces inherit the host's forwarding setting; the subnet router
# must enable it and restore it.
in_ns b sysctl -qw net.ipv4.ip_forward=0

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
for node in web lan; do
  ip netns exec "$(ns "$node")" python3 "$work/web.py" >"$work/$node-web.log" 2>&1 &
  pids+=($!)
done

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=Porta subnet test CA" \
  -keyout "$work/ca.key" -out "$work/ca.pem" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -subj "/CN=172.31.0.2" \
  -keyout "$work/server.key" -out "$work/server.csr" >/dev/null 2>&1
openssl x509 -req -in "$work/server.csr" -CA "$work/ca.pem" -CAkey "$work/ca.key" \
  -CAcreateserial -days 1 -extfile <(printf 'subjectAltName=IP:172.31.0.2,IP:172.31.1.2\n') \
  -out "$work/server.crt" >/dev/null 2>&1
openssl rand -hex 24 >"$work/alpha.token"

ip netns exec "$(ns gateway)" env \
  PORTA_TOKEN="$(<"$work/alpha.token")" PORTA_ADMIN_TOKEN="$admin_token" \
  "$server_binary" --listen ":$port" --admin-listen 127.0.0.1:9090 \
  --tls-cert "$work/server.crt" --tls-key "$work/server.key" \
  --client-registry "$work/clients.json" --lease-state "$work/leases.json" \
  --interface porta0 --egress-interface east --pool 10.66.0.0/24 --dns 192.0.2.53 \
  >>"$work/gateway.log" 2>&1 &
gateway_pid=$!
for _ in $(seq 1 100); do
  in_ns gateway ip link show dev porta0 >/dev/null 2>&1 && break
  sleep 0.1
done
in_ns gateway env PORTA_RUNTIME_DIRECTORY="$work/runtime" \
  "$repository_root/scripts/server-up.sh" porta0 10.66.0.1/24 10.66.0.0/24 east "$port" \
  >>"$work/gateway.log" 2>&1
for _ in $(seq 1 60); do
  in_ns gateway curl -fsS --max-time 5 http://127.0.0.1:9090/readyz >/dev/null 2>&1 && break
  sleep 1
done
in_ns gateway curl -fsS --max-time 5 http://127.0.0.1:9090/readyz >/dev/null
echo "gateway is ready"

admin_api() {
  in_ns gateway curl -fsS --max-time 10 -H "Authorization: Bearer $admin_token" \
    -H "Content-Type: application/json" "$@"
}
json() { python3 -c "import json, sys; print($1)"; }

alpha=$(admin_api http://127.0.0.1:9090/api/clients | json 'json.load(sys.stdin)["clients"][0]["id"]')
created=$(admin_api -X POST --data '{"name":"Beta","max_devices":5}' http://127.0.0.1:9090/api/clients)
beta=$(json 'json.load(sys.stdin)["client"]["id"]' <<<"$created")
json 'json.load(sys.stdin)["token"]' <<<"$created" >"$work/beta.token"

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

# Starts the client in node $1 for account token $2; extra options follow.
start_client() {
  local node=$1 token=$2
  shift 2
  local server=172.31.0.2
  [[ $node == b ]] && server=172.31.1.2
  install -d "/etc/netns/$(ns "$node")"
  printf 'nameserver 127.0.0.53\n' >"/etc/netns/$(ns "$node")/resolv.conf"
  install -d -m 0700 "$work/$node"
  ip netns exec "$(ns "$node")" env PORTA_TOKEN="$(<"$work/$token.token")" PATH="$work/bin:$PATH" \
    "$client_binary" --server "https://$server:$port" --ca "$work/ca.pem" \
    --identity "$work/$node/identity.json" --network-state "$work/$node/network-state.json" \
    --interface porta-ci0 --transport "$transport" "$@" >"$work/client-$node.log" 2>&1 &
  client_pids[$node]=$!
}
# Counts tunnel setups; the connected line itself repeats with progress.
connections() { grep -c "Configuring network" "$work/client-$1.log" 2>/dev/null || true; }
# Waits until client $1 has connected more than $2 times and prints its lease.
wait_connected() {
  local node=$1 after=${2:-0}
  for _ in $(seq 1 60); do
    if (( $(connections "$node") > after )) &&
      tail -n 1 "$work/client-$node.log" | grep -q "connected address="; then
      sed -n 's/.*connected address=\([0-9.]*\).*/\1/p' "$work/client-$node.log" | tail -n 1
      return 0
    fi
    kill -0 "${client_pids[$node]}" 2>/dev/null || { echo "client $node exited" >&2; return 1; }
    sleep 1
  done
  echo "client $node did not connect" >&2
  return 1
}

start_client b beta --subnet-router
wait_connected b >/dev/null
device_b=$(admin_api http://127.0.0.1:9090/api/clients |
  json "next(c for c in json.load(sys.stdin)['clients'] if c['id'] == '$beta')['devices'][0]['id']")
before=$(connections b)
admin_api -X PUT --data '{"subnets":["10.30.0.0/24"]}' \
  "http://127.0.0.1:9090/api/clients/$beta/devices/$device_b/subnets" >/dev/null
lease_b=$(wait_connected b "$before")
[[ $(in_ns b sysctl -n net.ipv4.ip_forward) == 1 ]] || { echo "subnet router did not enable forwarding" >&2; exit 1; }
start_client a alpha
lease_a=$(wait_connected a)
echo "clients connected: A=$lease_a, subnet router B=$lease_b"

seen_from_a() { in_ns a curl -fsS --max-time "${2:-3}" "http://$1:8080/" 2>/dev/null || true; }
# Retries while policy changes reconnect the clients.
expect_from_a() {
  local address=$1 want=$2 what=$3 seen=
  for _ in $(seq 1 30); do
    seen=$(seen_from_a "$address" 2)
    [[ $seen == "$want" ]] && return 0
    sleep 1
  done
  echo "$what: saw '${seen}', want '${want:-nothing}'" >&2
  exit 1
}
expect_refused_from_a() {
  local address=$1 what=$2
  sleep 3
  local seen
  seen=$(seen_from_a "$address" 3)
  [[ -z $seen ]] || { echo "$what: reached $address (seen as $seen)" >&2; exit 1; }
}

expect_from_a 172.31.9.2 172.31.9.1 "Internet request from A"
expect_refused_from_a 10.30.0.5 "LAN behind another account"
if in_ns a ping -n -c 1 -W 2 "$lease_b" >/dev/null 2>&1; then
  echo "A reached another account's device without a shared group" >&2
  exit 1
fi
echo "accounts without a shared group cannot reach each other or the subnet"

for account in "$alpha" "$beta"; do
  admin_api -X PUT --data '{"group":"team"}' \
    "http://127.0.0.1:9090/api/clients/$account/access" >/dev/null
done
expect_from_a 10.30.0.5 10.30.0.1 "LAN request through the subnet router"
lease_a=$(sed -n 's/.*connected address=\([0-9.]*\).*/\1/p' "$work/client-a.log" | tail -n 1)
lease_b=$(sed -n 's/.*connected address=\([0-9.]*\).*/\1/p' "$work/client-b.log" | tail -n 1)
in_ns a ping -n -c 2 -W 5 "$lease_b" >/dev/null
echo "a shared group reaches the peer and its LAN, masqueraded by the subnet router"

admin_api -X PUT --data '{"group":"team","deny":["10.30.0.0/24"]}' \
  "http://127.0.0.1:9090/api/clients/$alpha/access" >/dev/null
expect_from_a 172.31.9.2 172.31.9.1 "Internet request after the deny list"
expect_refused_from_a 10.30.0.5 "denied LAN"
admin_api -X PUT --data '{"group":"team","allow":["10.30.0.0/24"]}' \
  "http://127.0.0.1:9090/api/clients/$alpha/access" >/dev/null
expect_from_a 10.30.0.5 10.30.0.1 "allowed LAN"
expect_refused_from_a 172.31.9.2 "destination outside the allow list"
echo "deny and allow lists are enforced"

# A port rule admits the LAN web server but not ping.
admin_api -X PUT --data '{"group":"team","allow":["10.30.0.0/24 tcp/8080"]}' \
  "http://127.0.0.1:9090/api/clients/$alpha/access" >/dev/null
expect_from_a 10.30.0.5 10.30.0.1 "TCP 8080 under a port rule"
if in_ns a ping -n -c 2 -W 2 10.30.0.5 >/dev/null 2>&1; then
  echo "a tcp/8080 rule let ICMP through" >&2
  exit 1
fi
echo "port and protocol rules admit only the named service"

kill -INT "${client_pids[b]}"
wait "${client_pids[b]}" 2>/dev/null || true
unset 'client_pids[b]'
[[ $(in_ns b sysctl -n net.ipv4.ip_forward) == 0 ]] || { echo "subnet router left forwarding on" >&2; exit 1; }
expect_refused_from_a 10.30.0.5 "LAN after the subnet router disconnected"
echo "the subnet router restores forwarding and its LAN becomes unreachable when it leaves"
echo "subnet router test passed ($transport)"
