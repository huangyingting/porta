#!/usr/bin/env bash
# End-to-end dual-stack test using network namespaces and real binaries.
#
#   alpha --west--.                       .--east-- web (192.0.2.80,
#                  gateway (fd66:1::/64) -          2001:db8:80::80)
#   beta  --north-'                       '
#   alpha --leak-- web (the client's own IPv6 network, to expose leaks)
#
# The gateway gives clients IPv6 from fd66:1::/64 and masquerades it. Over
# the tunnel the web server sees the gateway's addresses for both families,
# never the client's own IPv6 address; devices of one account reach each
# other over IPv6 too. Without an IPv6 pool a full tunnel blocks IPv6 rather
# than leaking it, and a split tunnel routes only its IPv6 prefixes.
#
# Usage: sudo [PORTA_IPV6_TRANSPORT=auto|h3|h2] scripts/test-ipv6.sh \
#          [path-to-porta-server] [path-to-porta-client]
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "run with sudo" >&2; exit 2; }
repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
server_binary=$(realpath "${1:-$repository_root/rust/target/debug/porta-server}")
client_binary=$(realpath "${2:-$repository_root/rust/target/debug/porta-client}")
for binary in "$server_binary" "$client_binary"; do
  [[ -x $binary ]] || { echo "missing executable: $binary (build the workspace first)" >&2; exit 2; }
done
for command in curl ip nft openssl python3 ping; do
  command -v "$command" >/dev/null || { echo "missing required command: $command" >&2; exit 2; }
done

transport=${PORTA_IPV6_TRANSPORT:-auto}
[[ $transport =~ ^(auto|h3|h2)$ ]] || { echo "invalid PORTA_IPV6_TRANSPORT" >&2; exit 2; }
port=8443
suffix=$$
work=$(mktemp -d /tmp/porta-ipv6.XXXXXX)
chmod 0700 "$work"
pids=()
gateway_pid=
declare -A client_pids=()
admin_token=admin-token-0123456789abcdef
web4=192.0.2.80
web6=2001:db8:80::80
pool6=fd66:1::/64

ns() { printf 'p6%s-%s' "$suffix" "$1"; }
in_ns() { local name=$1; shift; ip netns exec "$(ns "$name")" "$@"; }

stop_client() {
  local client=$1
  [[ -n ${client_pids[$client]:-} ]] || return 0
  kill -INT "${client_pids[$client]}" 2>/dev/null || true
  wait "${client_pids[$client]}" 2>/dev/null || true
  unset "client_pids[$client]"
}
stop_gateway() {
  [[ -n $gateway_pid ]] || return 0
  kill "$gateway_pid" 2>/dev/null || true
  wait "$gateway_pid" 2>/dev/null || true
  gateway_pid=
  in_ns gateway env PORTA_RUNTIME_DIRECTORY="$work/gateway/runtime" \
    "$repository_root/scripts/server-down.sh" porta0 east >>"$work/gateway.log" 2>&1
}
cleanup() {
  local status=$?
  trap - EXIT
  for client in "${!client_pids[@]}"; do
    stop_client "$client"
  done
  stop_gateway || true
  for pid in "${pids[@]}"; do
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  done
  for node in alpha beta gateway web; do
    ip netns delete "$(ns "$node")" 2>/dev/null || true
    rm -rf "/etc/netns/$(ns "$node")"
  done
  if [[ $status -ne 0 ]]; then
    echo "IPv6 test failed; logs:" >&2
    for log in "$work"/*.log; do
      [[ -f $log ]] || continue
      echo "==> $log" >&2
      grep -v "connected address=.*uploaded=" "$log" | tail -n 40 >&2
    done
  fi
  rm -rf "$work"
  exit "$status"
}
trap cleanup EXIT

for node in alpha beta gateway web; do
  ip netns add "$(ns "$node")"
  in_ns "$node" ip link set lo up
done
link() {
  local left=$1 left_name=$2 right=$3 right_name=$4
  ip link add "$left_name" netns "$(ns "$left")" type veth peer name "$right_name" netns "$(ns "$right")"
  in_ns "$left" ip link set dev "$left_name" up
  in_ns "$right" ip link set dev "$right_name" up
}
link alpha to-gw gateway west
link beta to-gw gateway north
link gateway east web from-gw
link alpha leak web to-alpha
in_ns alpha ip address add 172.31.0.1/30 dev to-gw
in_ns gateway ip address add 172.31.0.2/30 dev west
in_ns beta ip address add 172.31.1.1/30 dev to-gw
in_ns gateway ip address add 172.31.1.2/30 dev north
in_ns gateway ip address add 172.31.9.1/30 dev east
in_ns web ip address add 172.31.9.2/30 dev from-gw
in_ns gateway ip -6 address add 2001:db8:9::1/64 dev east nodad
in_ns web ip -6 address add 2001:db8:9::2/64 dev from-gw nodad
in_ns alpha ip -6 address add 2001:db8:5::1/64 dev leak nodad
in_ns web ip -6 address add 2001:db8:5::2/64 dev to-alpha nodad
in_ns web ip address add "$web4/32" dev lo
in_ns web ip -6 address add "$web6/128" dev lo nodad
in_ns alpha ip route add default via 172.31.0.2
in_ns beta ip route add default via 172.31.1.2
in_ns gateway ip route add default via 172.31.9.2
in_ns gateway ip -6 route add 2001:db8:80::/48 via 2001:db8:9::2
# The client's own network reaches the web server over IPv6 directly.
in_ns alpha ip -6 route add default via 2001:db8:5::2

cat >"$work/web.py" <<'PY'
import http.server
import socket


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        source = self.client_address[0].removeprefix("::ffff:")
        body = source.encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class DualStackServer(http.server.ThreadingHTTPServer):
    address_family = socket.AF_INET6

    def server_bind(self):
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        super().server_bind()


DualStackServer(("::", 8080), Handler).serve_forever()
PY
# Background jobs run `ip netns exec` directly so that $! is the program
# itself, which then receives the signals that stop it.
ip netns exec "$(ns web)" python3 "$work/web.py" >"$work/web.log" 2>&1 &
pids+=($!)

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=Porta IPv6 test CA" \
  -keyout "$work/ca.key" -out "$work/ca.pem" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -subj "/CN=gateway" \
  -keyout "$work/gateway.key" -out "$work/gateway.csr" >/dev/null 2>&1
openssl x509 -req -in "$work/gateway.csr" -CA "$work/ca.pem" -CAkey "$work/ca.key" \
  -CAcreateserial -days 1 -extfile <(printf 'subjectAltName=IP:172.31.0.2,IP:172.31.1.2\n') \
  -out "$work/gateway.crt" >/dev/null 2>&1
openssl rand -hex 24 >"$work/token"

# start_gateway [--ipv6] [porta-server options...]
start_gateway() {
  local ipv6=false up_options=()
  if [[ ${1:-} == --ipv6 ]]; then
    ipv6=true
    shift
    set -- --ipv6-pool "$pool6" "$@"
    up_options=(--ipv6 fd66:1::1/64 "$pool6")
  fi
  install -d -m 0700 "$work/gateway"
  : >"$work/gateway.log"
  ip netns exec "$(ns gateway)" env PORTA_TOKEN="$(<"$work/token")" PORTA_ADMIN_TOKEN="$admin_token" \
    "$server_binary" --listen ":$port" --admin-listen 127.0.0.1:9090 \
    --tls-cert "$work/gateway.crt" --tls-key "$work/gateway.key" \
    --client-registry "$work/gateway/clients.json" --lease-state "$work/gateway/leases.json" \
    --interface porta0 --egress-interface east --pool 10.66.0.0/24 --dns 192.0.2.53 \
    "$@" >>"$work/gateway.log" 2>&1 &
  gateway_pid=$!
  for _ in $(seq 1 100); do
    in_ns gateway ip link show dev porta0 >/dev/null 2>&1 && break
    sleep 0.1
  done
  in_ns gateway env PORTA_RUNTIME_DIRECTORY="$work/gateway/runtime" \
    "$repository_root/scripts/server-up.sh" porta0 10.66.0.1/24 10.66.0.0/24 east "$port" \
    "${up_options[@]}" >>"$work/gateway.log" 2>&1
  for _ in $(seq 1 60); do
    in_ns gateway curl -fsS --max-time 5 http://127.0.0.1:9090/readyz >/dev/null 2>&1 && return 0
    sleep 1
  done
  in_ns gateway curl -sS --max-time 5 http://127.0.0.1:9090/readyz >&2 || true
  echo "gateway did not become ready (ipv6=$ipv6)" >&2
  return 1
}

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
for client in alpha beta; do
  install -d "/etc/netns/$(ns "$client")"
  printf 'nameserver 127.0.0.53\n' >"/etc/netns/$(ns "$client")/resolv.conf"
  install -d -m 0700 "$work/$client"
done
start_client() {
  local client=$1 server=$2
  : >"$work/$client.log"
  ip netns exec "$(ns "$client")" env PORTA_TOKEN="$(<"$work/token")" PATH="$work/bin:$PATH" \
    "$client_binary" --server "https://$server:$port" --ca "$work/ca.pem" \
    --identity "$work/$client/identity.json" --network-state "$work/$client/network-state.json" \
    --interface porta-ci0 --transport "$transport" >>"$work/$client.log" 2>&1 &
  client_pids[$client]=$!
  for _ in $(seq 1 60); do
    grep -q "porta-client: connected address=" "$work/$client.log" && return 0
    kill -0 "${client_pids[$client]}" 2>/dev/null || { echo "client $client exited" >&2; return 1; }
    sleep 1
  done
  echo "client $client did not connect" >&2
  return 1
}
seen() {
  local client=$1 url=$2
  shift 2
  in_ns "$client" curl -fsS --max-time 3 "$@" "$url" 2>/dev/null || true
}
expect_seen() {
  local client=$1 url=$2 want=$3 what=$4 observed=
  shift 4
  for _ in $(seq 1 20); do
    observed=$(seen "$client" "$url" "$@")
    [[ $observed == "$want" ]] && return 0
    sleep 0.5
  done
  echo "$what: web server saw '${observed}', want '$want'" >&2
  exit 1
}

start_gateway --ipv6
start_client alpha 172.31.0.2
grep -q "ipv6=fd66:1::2/128" "$work/alpha.log" || {
  echo "the client did not receive its IPv6 address" >&2
  exit 1
}
in_ns alpha ip -6 address show dev porta-ci0 | grep -q "fd66:1::2/128"
expect_seen alpha "http://[$web6]:8080/" 2001:db8:9::1 "IPv6 through the tunnel"
expect_seen alpha "http://$web4:8080/" 172.31.9.1 "IPv4 through the tunnel"
in_ns alpha ping -6 -c 1 -W 3 fd66:1::1 >/dev/null
echo "IPv6 reaches the web through the gateway and never the client's own network"

# A large download exercises IPv6 path MTU handling without fragmentation.
dd if=/dev/urandom of="$work/large.bin" bs=1k count=512 status=none
ip netns exec "$(ns web)" python3 -m http.server --directory "$work" --bind :: 8081 >"$work/files.log" 2>&1 &
pids+=($!)
sleep 1
in_ns alpha curl -fsS --max-time 30 -o "$work/downloaded.bin" "http://[$web6]:8081/large.bin"
cmp -s "$work/large.bin" "$work/downloaded.bin" || { echo "IPv6 download was corrupted" >&2; exit 1; }
echo "large IPv6 transfers complete"

# Devices of one account reach each other over IPv6.
start_client beta 172.31.1.2
beta6=$(sed -n 's/.*ipv6=\(fd66:1::[0-9a-f]*\)\/128.*/\1/p' "$work/beta.log" | head -n 1)
[[ -n $beta6 && $beta6 != fd66:1::2 ]] || { echo "the second device has no distinct IPv6 address" >&2; exit 1; }
in_ns alpha ping -6 -c 1 -W 3 "$beta6" >/dev/null
in_ns beta ping -6 -c 1 -W 3 fd66:1::2 >/dev/null
echo "devices of one account reach each other over IPv6"
stop_client beta

# A gateway without IPv6 blocks it in a full tunnel instead of leaking it.
stop_client alpha
stop_gateway
start_gateway
start_client alpha 172.31.0.2
if grep -q "ipv6=" "$work/alpha.log"; then
  echo "an IPv4-only gateway assigned IPv6" >&2
  exit 1
fi
expect_seen alpha "http://$web4:8080/" 172.31.9.1 "IPv4 through an IPv4-only gateway"
leaked=$(seen alpha "http://[$web6]:8080/")
[[ -z $leaked ]] || { echo "IPv6 leaked around the full tunnel: web server saw $leaked" >&2; exit 1; }
echo "a full tunnel without IPv6 blocks IPv6 instead of leaking it"

# A dual-stack split tunnel routes only its IPv6 prefixes.
stop_client alpha
stop_gateway
start_gateway --ipv6 --route "$web4/32" --route 2001:db8:80::/48
start_client alpha 172.31.0.2
expect_seen alpha "http://[$web6]:8080/" 2001:db8:9::1 "IPv6 split route through the tunnel"
expect_seen alpha "http://[2001:db8:5::2]:8080/" 2001:db8:5::1 "IPv6 outside the split routes"
echo "a dual-stack split tunnel routes only its IPv6 prefixes"

stop_client alpha
if in_ns alpha ip -6 route show | grep -q porta-ci0; then
  echo "IPv6 tunnel routes remained after disconnect" >&2
  exit 1
fi
expect_seen alpha "http://[$web6]:8080/" 2001:db8:5::1 "IPv6 after disconnect"
echo "IPv6 test passed ($transport)"
