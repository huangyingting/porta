#!/usr/bin/env bash
# End-to-end split tunnel test using network namespaces and real binaries.
#
#   client --east/west-- gateway --corp-- corp (10.20.0.10, behind the gateway)
#      \
#       `--pub/pub-- public (172.31.9.2, the client's default route; it also
#                            answers on 10.20.0.10 to expose any leak)
#
# The gateway advertises only 10.20.0.0/16 and the corp.example DNS domain.
# Corp traffic must go through the tunnel (the corp server sees the gateway's
# address), other traffic must go direct (the public server sees the client's
# own address), and corp traffic must fail closed rather than leak to the
# public network while the gateway is down. A clean disconnect must restore
# the host's own routing.
#
# Usage: sudo [PORTA_SPLIT_TRANSPORT=auto|h3|h2] scripts/test-split-tunnel.sh \
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

transport=${PORTA_SPLIT_TRANSPORT:-auto}
[[ $transport =~ ^(auto|h3|h2)$ ]] || { echo "invalid PORTA_SPLIT_TRANSPORT" >&2; exit 2; }
port=8443
suffix=$$
work=$(mktemp -d /tmp/porta-split.XXXXXX)
chmod 0700 "$work"
pids=()
gateway_pid=
client_pid=

ns() { printf 'ps%s-%s' "$suffix" "$1"; }
in_ns() { local name=$1; shift; ip netns exec "$(ns "$name")" "$@"; }

cleanup() {
  local status=$?
  trap - EXIT
  [[ -n $client_pid ]] && { kill -INT "$client_pid" 2>/dev/null || true; wait "$client_pid" 2>/dev/null || true; }
  [[ -n $gateway_pid ]] && { kill "$gateway_pid" 2>/dev/null || true; wait "$gateway_pid" 2>/dev/null || true; }
  for pid in "${pids[@]}"; do
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  done
  for node in client gateway corp public; do
    ip netns delete "$(ns "$node")" 2>/dev/null || true
    rm -rf "/etc/netns/$(ns "$node")"
  done
  if [[ $status -ne 0 ]]; then
    echo "split tunnel test failed; logs:" >&2
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

for node in client gateway corp public; do
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
link client east 172.31.0.1/30 gateway west 172.31.0.2/30
link gateway corp 10.20.0.1/24 corp west 10.20.0.10/24
link client pub 172.31.9.1/30 public pub 172.31.9.2/30
in_ns client ip route add default via 172.31.9.2
in_ns corp ip route add default via 10.20.0.1
# Gateway readiness requires a default route through its egress interface.
in_ns gateway ip route add default via 10.20.0.10
# The public network also answers on the corp address, so a corp request
# that bypasses the tunnel is visible instead of merely failing.
in_ns public ip address add 10.20.0.10/32 dev lo

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
for node in corp public; do
  ip netns exec "$(ns "$node")" python3 "$work/web.py" >"$work/$node-web.log" 2>&1 &
  pids+=($!)
done

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=Porta split test CA" \
  -keyout "$work/ca.key" -out "$work/ca.pem" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -subj "/CN=172.31.0.2" \
  -keyout "$work/server.key" -out "$work/server.csr" >/dev/null 2>&1
openssl x509 -req -in "$work/server.csr" -CA "$work/ca.pem" -CAkey "$work/ca.key" \
  -CAcreateserial -days 1 -extfile <(printf 'subjectAltName=IP:172.31.0.2\n') \
  -out "$work/server.crt" >/dev/null 2>&1
openssl rand -hex 24 >"$work/token"

start_gateway() {
  ip netns exec "$(ns gateway)" env \
    PORTA_TOKEN="$(<"$work/token")" PORTA_ADMIN_TOKEN=admin-token-0123456789abcdef \
    "$server_binary" --listen ":$port" --admin-listen 127.0.0.1:9090 \
    --tls-cert "$work/server.crt" --tls-key "$work/server.key" \
    --client-registry "$work/clients.json" --lease-state "$work/leases.json" \
    --interface porta0 --egress-interface corp --pool 10.66.0.0/24 \
    --dns 10.20.0.10 --route 10.20.0.0/16 --dns-domain corp.example \
    >>"$work/gateway.log" 2>&1 &
  gateway_pid=$!
  for _ in $(seq 1 100); do
    in_ns gateway ip link show dev porta0 >/dev/null 2>&1 && break
    sleep 0.1
  done
  in_ns gateway env PORTA_RUNTIME_DIRECTORY="$work/runtime" \
    "$repository_root/scripts/server-up.sh" porta0 10.66.0.1/24 10.66.0.0/24 corp "$port" \
    >>"$work/gateway.log" 2>&1
  for _ in $(seq 1 60); do
    in_ns gateway curl -fsS --max-time 5 http://127.0.0.1:9090/readyz >/dev/null 2>&1 && return 0
    sleep 1
  done
  in_ns gateway curl -sS --max-time 5 http://127.0.0.1:9090/readyz >&2 || true
  echo "gateway did not become ready" >&2
  return 1
}

stop_gateway() {
  kill "$gateway_pid"
  wait "$gateway_pid" 2>/dev/null || true
  gateway_pid=
  in_ns gateway env PORTA_RUNTIME_DIRECTORY="$work/runtime" \
    "$repository_root/scripts/server-down.sh" porta0 corp >>"$work/gateway.log" 2>&1
}

# Fetches the source address a web server saw, or nothing on failure.
seen_by() {
  in_ns client curl -fsS --max-time "${2:-5}" "http://$1:8080/" 2>/dev/null || true
}

expect_seen() {
  local address=$1 want=$2 what=$3
  local seen
  seen=$(seen_by "$address" 10)
  [[ $seen == "$want" ]] || { echo "$what: server saw '${seen}', want $want" >&2; exit 1; }
}

start_gateway
echo "gateway is ready"
in_ns gateway curl -fsS --max-time 10 -H "Authorization: Bearer admin-token-0123456789abcdef" \
  http://127.0.0.1:9090/api/gateway | python3 -c '
import json, sys
status = json.load(sys.stdin)
assert status["routes"] == ["10.20.0.0/16"], status
assert status["dns_domains"] == ["corp.example"], status'
echo "the admin API reports the advertised split routing"

# Fake only systemd-resolved's CLI, recording what the client configures.
install -d "$work/bin"
cat >"$work/bin/resolvectl" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$*" >>"$work/resolvectl.calls"
case "\${1:-}" in
  status|revert|default-route) exit 0 ;;
  dns|domain) [[ \$# == 2 ]] && printf 'Link 2 (%s):\n' "\$2"; exit 0 ;;
  *) exit 2 ;;
esac
EOF
chmod 0755 "$work/bin/resolvectl"
install -d "/etc/netns/$(ns client)"
printf 'nameserver 127.0.0.53\n' >"/etc/netns/$(ns client)/resolv.conf"

# Before connecting, corp requests follow the default route to the public net.
expect_seen 10.20.0.10 172.31.9.1 "corp request before connecting"

ip netns exec "$(ns client)" env PORTA_TOKEN="$(<"$work/token")" PATH="$work/bin:$PATH" \
  "$client_binary" --server "https://172.31.0.2:$port" --ca "$work/ca.pem" \
  --identity "$work/identity.json" --network-state "$work/network-state.json" \
  --interface porta-ci0 --transport "$transport" >"$work/client.log" 2>&1 &
client_pid=$!
for _ in $(seq 1 60); do
  grep -qs "connected address=" "$work/client.log" && break
  kill -0 "$client_pid" 2>/dev/null || { echo "client exited" >&2; exit 1; }
  sleep 1
done
grep -qs "connected address=" "$work/client.log" || { echo "client did not connect" >&2; exit 1; }
echo "client connected"

route_device() { in_ns client ip -o route get "$1" | sed -n 's/.* dev \([^ ]*\).*/\1/p'; }
[[ $(route_device 10.20.0.10) == porta-ci0 ]] || { echo "corp traffic is not routed into the tunnel" >&2; exit 1; }
[[ $(route_device 172.31.9.2) == pub ]] || { echo "public traffic is routed into the tunnel" >&2; exit 1; }
[[ $(route_device 192.0.2.1) == pub ]] || { echo "default traffic is routed into the tunnel" >&2; exit 1; }
# Peers and their subnets stay reachable: the client pool is routed too.
[[ $(route_device 10.66.0.1) == porta-ci0 ]] || { echo "the client pool is not routed into the tunnel" >&2; exit 1; }
expect_seen 10.20.0.10 10.20.0.1 "corp request through the tunnel"
expect_seen 172.31.9.2 172.31.9.1 "public request outside the tunnel"
echo "only the advertised prefix uses the tunnel; other traffic goes direct"

grep -qx "domain porta-ci0 ~corp.example" "$work/resolvectl.calls" || {
  echo "client did not scope tunnel DNS to corp.example:" >&2
  cat "$work/resolvectl.calls" >&2
  exit 1
}
grep -qx "dns porta-ci0 10.20.0.10" "$work/resolvectl.calls" || {
  echo "client did not configure the tunnel resolver" >&2
  exit 1
}
if grep -q "domain porta-ci0 ~\.$" "$work/resolvectl.calls"; then
  echo "split tunnel claimed every DNS name" >&2
  exit 1
fi
echo "tunnel DNS is scoped to corp.example"

stop_gateway
for _ in $(seq 1 30); do
  grep -qs "reconnecting" "$work/client.log" && break
  sleep 1
done
leak=$(seen_by 10.20.0.10 3)
[[ -z $leak ]] || { echo "corp request leaked outside the tunnel while it was down (seen as $leak)" >&2; exit 1; }
expect_seen 172.31.9.2 172.31.9.1 "public request while the tunnel is down"
echo "corp traffic fails closed while the gateway is down; other traffic still flows"

start_gateway
for _ in $(seq 1 60); do
  [[ $(seen_by 10.20.0.10 3) == 10.20.0.1 ]] && break
  sleep 1
done
expect_seen 10.20.0.10 10.20.0.1 "corp request after the gateway returned"
echo "client recovered the split tunnel after the gateway restarted"

kill -INT "$client_pid"
wait "$client_pid" 2>/dev/null || true
client_pid=
if in_ns client nft list tables | grep -q 'inet porta_'; then
  echo "client left its guard table behind" >&2
  exit 1
fi
expect_seen 10.20.0.10 172.31.9.1 "corp request after disconnecting"
echo "disconnect restored the host's own routing"
echo "split tunnel test passed ($transport)"
