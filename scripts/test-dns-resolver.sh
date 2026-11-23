#!/usr/bin/env bash
# End-to-end test of the gateway's built-in DNS resolver using network
# namespaces and real binaries.
#
#   client A, client B (account alpha) --.
#                                          gateway (--dns-resolver) -- web
#   client C (account beta) --------------'          (fake upstream DNS)
#
# Clients receive the gateway address as their DNS server. The test checks
# device names and reverse lookups for peers only, forwarding to the
# upstream resolver over UDP and TCP, blocklisted domains, that an access
# group makes another account's devices resolvable, and that the resolver
# is unreachable from outside the tunnel.
#
# Usage: sudo scripts/test-dns-resolver.sh [path-to-porta-server] [path-to-porta-client]
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "run with sudo" >&2; exit 2; }
repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
server_binary=$(realpath "${1:-$repository_root/rust/target/debug/porta-server}")
client_binary=$(realpath "${2:-$repository_root/rust/target/debug/porta-client}")
for binary in "$server_binary" "$client_binary"; do
  [[ -x $binary ]] || { echo "missing executable: $binary (build the workspace first)" >&2; exit 2; }
done
for command in curl dig ip nft openssl python3; do
  command -v "$command" >/dev/null || { echo "missing required command: $command" >&2; exit 2; }
done

port=8443
suffix=$$
work=$(mktemp -d /tmp/porta-dns.XXXXXX)
chmod 0700 "$work"
pids=()
gateway_pid=
declare -A client_pids=()
admin_token=admin-token-0123456789abcdef

ns() { printf 'pd%s-%s' "$suffix" "$1"; }
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
  for node in a b c gateway web; do
    ip netns delete "$(ns "$node")" 2>/dev/null || true
    rm -rf "/etc/netns/$(ns "$node")"
  done
  if [[ $status -ne 0 ]]; then
    echo "DNS resolver test failed; logs:" >&2
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

for node in a b c gateway web; do
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
link c east 172.31.2.1/30 gateway to-c 172.31.2.2/30
link gateway east 172.31.9.1/30 web west 172.31.9.2/30
in_ns a ip route add default via 172.31.0.2
in_ns b ip route add default via 172.31.1.2
in_ns c ip route add default via 172.31.2.2
in_ns gateway ip route add default via 172.31.9.2

# A fake upstream resolver that answers every A query with 192.0.2.10.
cat >"$work/upstream.py" <<'PY'
import socket

server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server.bind(("0.0.0.0", 53))
while True:
    query, peer = server.recvfrom(512)
    end = 12
    while query[end]:
        end += query[end] + 1
    end += 5
    reply = query[:2] + b"\x81\x80" + query[4:6] + b"\x00\x01\x00\x00\x00\x00" + query[12:end]
    reply += b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" + bytes([192, 0, 2, 10])
    server.sendto(reply, peer)
PY
ip netns exec "$(ns web)" python3 "$work/upstream.py" >"$work/upstream.log" 2>&1 &
pids+=($!)
printf '# test blocklist\n0.0.0.0 blocked.test\n' >"$work/blocklist.txt"

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=Porta DNS test CA" \
  -keyout "$work/ca.key" -out "$work/ca.pem" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -subj "/CN=porta-gateway" \
  -keyout "$work/server.key" -out "$work/server.csr" >/dev/null 2>&1
openssl x509 -req -in "$work/server.csr" -CA "$work/ca.pem" -CAkey "$work/ca.key" \
  -CAcreateserial -days 1 \
  -extfile <(printf 'subjectAltName=IP:172.31.0.2,IP:172.31.1.2,IP:172.31.2.2\n') \
  -out "$work/server.crt" >/dev/null 2>&1
openssl rand -hex 24 >"$work/alpha.token"

ip netns exec "$(ns gateway)" env \
  PORTA_TOKEN="$(<"$work/alpha.token")" PORTA_ADMIN_TOKEN="$admin_token" \
  "$server_binary" --listen ":$port" --admin-listen 127.0.0.1:9090 \
  --tls-cert "$work/server.crt" --tls-key "$work/server.key" \
  --client-registry "$work/clients.json" --lease-state "$work/leases.json" \
  --interface porta0 --egress-interface east --pool 10.66.0.0/24 \
  --dns-resolver --dns-upstream 172.31.9.2 --dns-blocklist "$work/blocklist.txt" \
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

start_client() {
  local node=$1 token=$2 server
  server=$(in_ns "$node" ip route show default | sed -n 's/default via \([0-9.]*\).*/\1/p')
  install -d "/etc/netns/$(ns "$node")"
  printf 'nameserver 127.0.0.53\n' >"/etc/netns/$(ns "$node")/resolv.conf"
  install -d -m 0700 "$work/$node"
  : >"$work/client-$node.log"
  ip netns exec "$(ns "$node")" env PORTA_TOKEN="$(<"$work/$token.token")" PATH="$work/bin:$PATH" \
    "$client_binary" --server "https://$server:$port" --ca "$work/ca.pem" \
    --identity "$work/$node/identity.json" --network-state "$work/$node/network-state.json" \
    --interface porta-ci0 >"$work/client-$node.log" 2>&1 &
  client_pids[$node]=$!
}
lease_of() { sed -n 's/.*connected address=\([0-9.]*\).*/\1/p' "$work/client-$1.log" | tail -n 1; }
start_client a alpha
start_client b alpha
start_client c beta
for node in a b c; do
  for _ in $(seq 1 60); do
    grep -qs "connected address=" "$work/client-$node.log" && break
    sleep 1
  done
  grep -qs "connected address=.* dns=10.66.0.1 " "$work/client-$node.log" || {
    echo "client $node did not receive the gateway as its DNS server" >&2
    exit 1
  }
done
lease_b=$(lease_of b)
echo "clients connected with the gateway as their resolver"

device_name() {
  admin_api http://127.0.0.1:9090/api/clients | python3 -c "
import json, sys
clients = json.load(sys.stdin)['clients']
client = next(c for c in clients if c['id'] == '$1')
print(next(d['dns_name'] for d in client['devices'] if d['assigned_address'] == '$2'))"
}
name_b=$(device_name "$alpha" "$lease_b")
[[ $name_b == *.porta.internal ]] || { echo "unexpected device name $name_b" >&2; exit 1; }
lookup() { in_ns a dig @10.66.0.1 +time=2 +tries=1 "$@" 2>&1 || true; }
answer() { in_ns a dig @10.66.0.1 +time=2 +tries=1 +short "$@" 2>/dev/null | tail -n 1 || true; }

[[ $(answer "$name_b") == "$lease_b" ]] || { echo "A could not resolve its peer $name_b" >&2; exit 1; }
[[ $(answer +tcp "$name_b") == "$lease_b" ]] || { echo "A could not resolve its peer over TCP" >&2; exit 1; }
[[ $(answer -x "$lease_b") == "$name_b." ]] || { echo "reverse lookup of $lease_b failed" >&2; exit 1; }
[[ $(answer www.example) == 192.0.2.10 ]] || { echo "the resolver did not forward www.example" >&2; exit 1; }
[[ $(answer +tcp www.example) == 192.0.2.10 ]] || { echo "the resolver did not forward over TCP" >&2; exit 1; }
lookup ads.blocked.test | grep -q "status: NXDOMAIN" || { echo "a blocklisted subdomain resolved" >&2; exit 1; }
lookup missing.porta.internal | grep -q "status: NXDOMAIN" || { echo "an unknown device name resolved" >&2; exit 1; }
echo "peers, reverse names, forwarding and the blocklist work"

lease_c=$(lease_of c)
name_c=$(device_name "$beta" "$lease_c")
lookup "$name_c" | grep -q "status: NXDOMAIN" || {
  echo "A resolved a device of another account without a shared group" >&2
  exit 1
}
for account in "$alpha" "$beta"; do
  admin_api -X PUT --data '{"group":"team"}' "http://127.0.0.1:9090/api/clients/$account/access" >/dev/null
done
for _ in $(seq 1 30); do
  lease_c=$(lease_of c)
  [[ $(answer "$name_c") == "$lease_c" ]] && break
  sleep 1
done
[[ $(answer "$name_c") == "$(lease_of c)" ]] || { echo "a shared group did not make $name_c resolvable" >&2; exit 1; }
echo "another account's devices resolve only once the accounts share a group"

# Even with a route to the gateway address, other networks get no answers.
in_ns web ip route add 10.66.0.0/24 via 172.31.9.1
if in_ns web dig @10.66.0.1 +time=2 +tries=1 +short www.example >/dev/null 2>&1; then
  echo "the resolver answered a query from outside the tunnel" >&2
  exit 1
fi
echo "the resolver is unreachable from outside the tunnel"
echo "DNS resolver test passed"
