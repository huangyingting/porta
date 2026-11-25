#!/usr/bin/env bash
# End-to-end transport relay test using network namespaces and real binaries.
#
#   client --west/east-- relay --south/north-- gateway --egress-- web (192.0.2.80)
#
# The client cannot reach the gateway directly: the relay forwards only what
# scripts/relay.sh relays, on another port. The client keeps the gateway's
# URL and certificate and dials the relay with --relay-address, over HTTP/3
# and HTTP/2. Leak protection lets only the relay through, and the client
# refuses a relay combined with backup gateways.
#
# Usage: sudo scripts/test-transport-relay.sh [path-to-porta-server] [path-to-porta-client]
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

port=8443
relay_port=9443
suffix=$$
work=$(mktemp -d /tmp/porta-relay.XXXXXX)
chmod 0700 "$work"
pids=()
gateway_pid=
client_pid=
web=192.0.2.80

ns() { printf 'pr%s-%s' "$suffix" "$1"; }
in_ns() { local name=$1; shift; ip netns exec "$(ns "$name")" "$@"; }

cleanup() {
  local status=$?
  trap - EXIT
  [[ -n $client_pid ]] && { kill -INT "$client_pid" 2>/dev/null || true; wait "$client_pid" 2>/dev/null || true; }
  if [[ -n $gateway_pid ]]; then
    kill "$gateway_pid" 2>/dev/null || true
    wait "$gateway_pid" 2>/dev/null || true
    in_ns gateway env PORTA_RUNTIME_DIRECTORY="$work/runtime" \
      "$repository_root/scripts/server-down.sh" porta0 egress >>"$work/gateway.log" 2>&1 || true
  fi
  for pid in "${pids[@]}"; do
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  done
  for node in client relay gateway web; do
    ip netns delete "$(ns "$node")" 2>/dev/null || true
    rm -rf "/etc/netns/$(ns "$node")"
  done
  if [[ $status -ne 0 ]]; then
    echo "transport relay test failed; logs:" >&2
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

for node in client relay gateway web; do
  ip netns add "$(ns "$node")"
  in_ns "$node" ip link set lo up
done
link() {
  local left=$1 left_name=$2 left_address=$3 right=$4 right_name=$5 right_address=$6
  ip link add "$left_name" netns "$(ns "$left")" type veth peer name "$right_name" netns "$(ns "$right")"
  in_ns "$left" ip address add "$left_address" dev "$left_name"
  in_ns "$right" ip address add "$right_address" dev "$right_name"
  in_ns "$left" ip link set "$left_name" up
  in_ns "$right" ip link set "$right_name" up
}
link client west 172.31.0.1/30 relay east 172.31.0.2/30
link relay south 172.31.1.1/30 gateway north 172.31.1.2/30
link gateway egress 172.31.9.1/30 web ingress 172.31.9.2/30
in_ns web ip address add "$web/32" dev lo
in_ns client ip route add default via 172.31.0.2
in_ns gateway ip route add default via 172.31.9.2

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

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=Porta relay test CA" \
  -keyout "$work/ca.key" -out "$work/ca.pem" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -subj "/CN=172.31.1.2" \
  -keyout "$work/server.key" -out "$work/server.csr" >/dev/null 2>&1
openssl x509 -req -in "$work/server.csr" -CA "$work/ca.pem" -CAkey "$work/ca.key" \
  -CAcreateserial -days 1 -extfile <(printf 'subjectAltName=IP:172.31.1.2\n') \
  -out "$work/server.crt" >/dev/null 2>&1
openssl rand -hex 24 >"$work/token"

ip netns exec "$(ns gateway)" env \
  PORTA_TOKEN="$(<"$work/token")" PORTA_ADMIN_TOKEN=admin-token-0123456789abcdef \
  "$server_binary" --listen ":$port" --admin-listen 127.0.0.1:9090 \
  --tls-cert "$work/server.crt" --tls-key "$work/server.key" \
  --client-registry "$work/clients.json" --lease-state "$work/leases.json" \
  --interface porta0 --egress-interface egress --pool 10.66.0.0/24 --dns 192.0.2.53 \
  >>"$work/gateway.log" 2>&1 &
gateway_pid=$!
for _ in $(seq 1 100); do
  in_ns gateway ip link show dev porta0 >/dev/null 2>&1 && break
  sleep 0.1
done
in_ns gateway env PORTA_RUNTIME_DIRECTORY="$work/runtime" \
  "$repository_root/scripts/server-up.sh" porta0 10.66.0.1/24 10.66.0.0/24 egress "$port" \
  >>"$work/gateway.log" 2>&1
for _ in $(seq 1 60); do
  in_ns gateway curl -fsS --max-time 5 http://127.0.0.1:9090/readyz >/dev/null 2>&1 && break
  sleep 1
done
echo "gateway is ready"

# The relay forwards only its relay port; the direct route is unusable.
in_ns relay "$repository_root/scripts/relay.sh" up "172.31.1.2:$port" --port "$relay_port" \
  --allow 172.31.0.0/30 >"$work/relay.log"
in_ns relay nft -f - <<'NFT'
table inet direct_blocked {
  chain forward {
    type filter hook forward priority filter; policy accept;
    ct original ip daddr 172.31.1.2 drop
  }
}
NFT
in_ns relay "$repository_root/scripts/relay.sh" status | grep -q "dnat ip to 172.31.1.2:$port"
if in_ns client curl -sS --max-time 3 --cacert "$work/ca.pem" -o /dev/null "https://172.31.1.2:$port/" 2>/dev/null; then
  echo "the client reached the gateway directly" >&2
  exit 1
fi
in_ns client curl -sS --max-time 5 --cacert "$work/ca.pem" -o /dev/null \
  --connect-to "172.31.1.2:$port:172.31.0.2:$relay_port" "https://172.31.1.2:$port/"
echo "the relay forwards to the gateway, which the client cannot reach directly"

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

# Replaces the calling (sub)shell, so a background client is signalled
# directly.
client() {
  exec ip netns exec "$(ns client)" env PORTA_TOKEN="$(<"$work/token")" PATH="$work/bin:$PATH" \
    "$client_binary" --server "https://172.31.1.2:$port" --ca "$work/ca.pem" \
    --identity "$work/identity.json" --network-state "$work/network-state.json" \
    --interface porta-ci0 "$@"
}
seen() { in_ns client curl -fsS --max-time 5 "http://$web:8080/" 2>/dev/null || true; }

for transport in h3 h2; do
  client --transport "$transport" --relay-address "172.31.0.2:$relay_port" >"$work/client-$transport.log" 2>&1 &
  client_pid=$!
  for _ in $(seq 1 60); do
    grep -qs "connected address=" "$work/client-$transport.log" && break
    kill -0 "$client_pid" 2>/dev/null || { echo "the $transport client exited" >&2; exit 1; }
    sleep 1
  done
  grep -qs "connected address=.* transport=$transport" "$work/client-$transport.log" || {
    echo "the $transport client did not connect through the relay" >&2
    exit 1
  }
  grep -q "relay 172.31.0.2:$relay_port forwards to https://172.31.1.2:$port/" "$work/client-$transport.log"
  [[ $(seen) == 172.31.9.1 ]] || { echo "traffic does not use the tunnel over $transport" >&2; exit 1; }
  guard=$(in_ns client nft list ruleset)
  grep -q "172.31.0.2" <<<"$guard" || { echo "leak protection does not let the relay through" >&2; exit 1; }
  if grep -q "172.31.1.2" <<<"$guard"; then
    echo "leak protection lets the gateway through instead of the relay" >&2
    exit 1
  fi
  kill -INT "$client_pid"
  wait "$client_pid" 2>/dev/null || true
  client_pid=
  if in_ns client nft list tables | grep -q 'inet porta_'; then
    echo "the client left its guard table behind" >&2
    exit 1
  fi
  echo "the client tunnels through the relay over $transport"
done

if (client --relay-address "172.31.0.2:$relay_port" --server "https://172.31.1.3:$port") \
  >"$work/client-backups.log" 2>&1; then
  echo "a relay with backup gateways was accepted" >&2
  exit 1
fi
grep -q "a relay forwards to one gateway" "$work/client-backups.log"
echo "a relay with backup gateways is refused"

in_ns relay "$repository_root/scripts/relay.sh" down >/dev/null
if in_ns relay nft list tables | grep -q porta_relay; then
  echo "relay.sh down left the relay behind" >&2
  exit 1
fi
echo "transport relay test passed"
