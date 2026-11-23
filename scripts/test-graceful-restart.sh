#!/usr/bin/env bash
# End-to-end test of in-place gateway restarts using network namespaces and
# real binaries.
#
#   client --west/east-- gateway --egress-- web (192.0.2.80)
#
# The gateway's binary is replaced, then the process gets SIGHUP. It must
# re-execute the new binary under the same PID, keep its TUN interface (same
# index, addresses and firewall rules) and listening sockets, and the client
# must resume over the same transport with the same lease within seconds.
#
# Usage: sudo [PORTA_RESTART_TRANSPORT=auto|h3|h2] scripts/test-graceful-restart.sh \
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

transport=${PORTA_RESTART_TRANSPORT:-auto}
[[ $transport =~ ^(auto|h3|h2)$ ]] || { echo "invalid PORTA_RESTART_TRANSPORT" >&2; exit 2; }
port=8443
suffix=$$
work=$(mktemp -d /tmp/porta-restart.XXXXXX)
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
  if [[ -n $client_pid ]]; then
    kill -INT "$client_pid" 2>/dev/null || true
    wait "$client_pid" 2>/dev/null || true
  fi
  if [[ -n $gateway_pid ]]; then
    kill "$gateway_pid" 2>/dev/null || true
    wait "$gateway_pid" 2>/dev/null || true
    in_ns gateway env PORTA_RUNTIME_DIRECTORY="$work/gateway/runtime" \
      "$repository_root/scripts/server-down.sh" porta0 egress >>"$work/gateway.log" 2>&1 || true
  fi
  for pid in "${pids[@]}"; do
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  done
  for node in client gateway web; do
    ip netns delete "$(ns "$node")" 2>/dev/null || true
    rm -rf "/etc/netns/$(ns "$node")"
  done
  if [[ $status -ne 0 ]]; then
    echo "graceful restart test failed; logs:" >&2
    for log in "$work"/*.log; do
      [[ -f $log ]] || continue
      echo "==> $log" >&2
      grep -v "connected address=.*uploaded=[1-9]" "$log" | tail -n 40 >&2
    done
  fi
  rm -rf "$work"
  exit "$status"
}
trap cleanup EXIT

for node in client gateway web; do
  ip netns add "$(ns "$node")"
  in_ns "$node" ip link set lo up
done
ip link add west netns "$(ns client)" type veth peer name east netns "$(ns gateway)"
ip link add egress netns "$(ns gateway)" type veth peer name ingress netns "$(ns web)"
in_ns client ip address add 172.31.0.1/30 dev west
in_ns gateway ip address add 172.31.0.2/30 dev east
in_ns gateway ip address add 172.31.9.1/30 dev egress
in_ns web ip address add 172.31.9.2/30 dev ingress
in_ns web ip address add "$web/32" dev lo
for pair in "client west" "gateway east" "gateway egress" "web ingress"; do
  read -r node interface <<<"$pair"
  in_ns "$node" ip link set dev "$interface" up
done
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

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=Porta restart test CA" \
  -keyout "$work/ca.key" -out "$work/ca.pem" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -subj "/CN=gateway" \
  -keyout "$work/gateway.key" -out "$work/gateway.csr" >/dev/null 2>&1
openssl x509 -req -in "$work/gateway.csr" -CA "$work/ca.pem" -CAkey "$work/ca.key" \
  -CAcreateserial -days 1 -extfile <(printf 'subjectAltName=IP:172.31.0.2\n') \
  -out "$work/gateway.crt" >/dev/null 2>&1
openssl rand -hex 24 >"$work/token"

# The gateway runs from a copy so that the test can replace the binary the
# way an upgrade does.
install -m 0755 "$server_binary" "$work/porta-server"
install -d -m 0700 "$work/gateway"
ip netns exec "$(ns gateway)" env PORTA_TOKEN="$(<"$work/token")" PORTA_ADMIN_TOKEN=admin-token-0123456789abcdef \
  "$work/porta-server" --listen ":$port" --admin-listen 127.0.0.1:9090 \
  --tls-cert "$work/gateway.crt" --tls-key "$work/gateway.key" \
  --client-registry "$work/gateway/clients.json" --lease-state "$work/gateway/leases.json" \
  --interface porta0 --egress-interface egress --pool 10.66.0.0/24 --dns 192.0.2.53 \
  >"$work/gateway.log" 2>&1 &
gateway_pid=$!
for _ in $(seq 1 100); do
  in_ns gateway ip link show dev porta0 >/dev/null 2>&1 && break
  sleep 0.1
done
in_ns gateway env PORTA_RUNTIME_DIRECTORY="$work/gateway/runtime" \
  "$repository_root/scripts/server-up.sh" porta0 10.66.0.1/24 10.66.0.0/24 egress "$port" \
  >>"$work/gateway.log" 2>&1
ready() {
  for _ in $(seq 1 60); do
    in_ns gateway curl -fsS --max-time 2 http://127.0.0.1:9090/readyz >/dev/null 2>&1 && return 0
    sleep 0.5
  done
  echo "the gateway is not ready" >&2
  return 1
}
ready

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
  "$client_binary" --server "https://172.31.0.2:$port" --ca "$work/ca.pem" \
  --identity "$work/client/identity.json" --network-state "$work/client/network-state.json" \
  --interface porta-ci0 --transport "$transport" >"$work/client.log" 2>&1 &
client_pid=$!

seen() { in_ns client curl -fsS --max-time 1 "http://$web:8080/" 2>/dev/null || true; }
for _ in $(seq 1 60); do
  [[ $(seen) == 172.31.9.1 ]] && break
  kill -0 "$client_pid" 2>/dev/null || { echo "client exited" >&2; exit 1; }
  sleep 0.5
done
[[ $(seen) == 172.31.9.1 ]] || { echo "the client never reached the web through the gateway" >&2; exit 1; }
first=$(grep -m 1 "connected address=" "$work/client.log")
address=$(sed -n 's/.*connected address=\([^ ]*\).*/\1/p' <<<"$first")
first_transport=$(sed -n 's/.*transport=\([^ ]*\).*/\1/p' <<<"$first")
index=$(in_ns gateway cat /sys/class/net/porta0/ifindex)
echo "connected as $address over $first_transport"

# Upgrade: replace the binary with a new file, then restart in place.
cp "$server_binary" "$work/porta-server.new"
mv -f "$work/porta-server.new" "$work/porta-server"
connected_before=$(grep -c "connected address=" "$work/client.log")
started=$(date +%s%N)
kill -HUP "$gateway_pid"
resumed=
for _ in $(seq 1 100); do
  if [[ $(seen) == 172.31.9.1 ]] && grep -q "adopted descriptors" "$work/gateway.log"; then
    resumed=$(date +%s%N)
    break
  fi
  sleep 0.1
done
[[ -n $resumed ]] || { echo "the client did not resume after the in-place restart" >&2; exit 1; }
elapsed=$(( (resumed - started) / 1000000 ))
echo "traffic resumed ${elapsed} ms after SIGHUP"
(( elapsed < 5000 )) || { echo "resuming took ${elapsed} ms" >&2; exit 1; }

kill -0 "$gateway_pid" 2>/dev/null || { echo "the gateway process exited instead of restarting in place" >&2; exit 1; }
[[ $(grep -c "Rust server core initialized" "$work/gateway.log") -eq 2 ]] || {
  echo "the gateway did not start a second time" >&2
  exit 1
}
grep -q "restarting in place" "$work/gateway.log"
[[ $(in_ns gateway cat /sys/class/net/porta0/ifindex) == "$index" ]] || {
  echo "the TUN interface was recreated" >&2
  exit 1
}
in_ns gateway ip -4 address show dev porta0 | grep -q "10.66.0.1/24"
in_ns gateway nft list table ip porta >/dev/null
ready
for _ in $(seq 1 20); do
  (( $(grep -c "connected address=" "$work/client.log") > connected_before )) && break
  sleep 0.25
done
last=$(grep "connected address=" "$work/client.log" | tail -n 1)
[[ $(sed -n 's/.*connected address=\([^ ]*\).*/\1/p' <<<"$last") == "$address" ]] || {
  echo "the lease changed across the restart: $last" >&2
  exit 1
}
[[ $(sed -n 's/.*transport=\([^ ]*\).*/\1/p' <<<"$last") == "$first_transport" ]] || {
  echo "the transport changed across the restart: $last" >&2
  exit 1
}
grep -q "gateway restarting\|Reconnecting" "$work/client.log"
echo "the gateway restarted in place with the same PID, interface, lease and transport"

# A second restart works the same way.
kill -HUP "$gateway_pid"
sleep 1
ready
for _ in $(seq 1 50); do
  [[ $(seen) == 172.31.9.1 ]] && break
  sleep 0.1
done
[[ $(seen) == 172.31.9.1 ]] || { echo "the client did not resume after a second restart" >&2; exit 1; }
echo "graceful restart test passed ($transport)"
