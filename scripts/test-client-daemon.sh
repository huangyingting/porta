#!/usr/bin/env bash
# End-to-end test of the Linux desktop service (`porta-client --daemon`)
# using network namespaces and real binaries.
#
#   client (daemon) --west/east-- gateway --egress-- web (192.0.2.80)
#      `--lan0-- printer (192.168.77.10), on the client's local network
#
# The test drives the daemon's control socket the way the desktop app does:
# it saves a profile, connects, checks that traffic uses the tunnel and that
# the snapshot reports it, disconnects, and checks that networking is
# restored. The full tunnel blocks the local printer until the profile allows
# the local network. A wrong token surfaces as a connection error, and only
# root and members of the control group may open the socket.
#
# Usage: sudo scripts/test-client-daemon.sh [path-to-porta-server] [path-to-porta-client]
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "run with sudo" >&2; exit 2; }
repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
server_binary=$(realpath "${1:-$repository_root/rust/target/debug/porta-server}")
client_binary=$(realpath "${2:-$repository_root/rust/target/debug/porta-client}")
for binary in "$server_binary" "$client_binary"; do
  [[ -x $binary ]] || { echo "missing executable: $binary (build the workspace first)" >&2; exit 2; }
done
for command in curl ip nft openssl python3 setpriv; do
  command -v "$command" >/dev/null || { echo "missing required command: $command" >&2; exit 2; }
done

port=8443
suffix=$$
work=$(mktemp -d /tmp/porta-daemon.XXXXXX)
chmod 0755 "$work"
pids=()
gateway_pid=
daemon_pid=
web=192.0.2.80
socket=$work/run/control.sock
control_group=nogroup
other_group=daemon

ns() { printf 'pd%s-%s' "$suffix" "$1"; }
in_ns() { local name=$1; shift; ip netns exec "$(ns "$name")" "$@"; }

cleanup() {
  local status=$?
  trap - EXIT
  if [[ -n $daemon_pid ]]; then
    kill "$daemon_pid" 2>/dev/null || true
    wait "$daemon_pid" 2>/dev/null || true
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
  for node in client gateway web printer; do
    ip netns delete "$(ns "$node")" 2>/dev/null || true
    rm -rf "/etc/netns/$(ns "$node")"
  done
  if [[ $status -ne 0 ]]; then
    echo "client daemon test failed; logs:" >&2
    for log in "$work"/*.log; do
      [[ -f $log ]] || continue
      echo "==> $log" >&2
      tail -n 30 "$log" >&2
    done
  fi
  rm -rf "$work"
  exit "$status"
}
trap cleanup EXIT

for node in client gateway web printer; do
  ip netns add "$(ns "$node")"
  in_ns "$node" ip link set lo up
done
ip link add lan0 netns "$(ns client)" type veth peer name lan netns "$(ns printer)"
in_ns client ip address add 192.168.77.1/24 dev lan0
in_ns printer ip address add 192.168.77.10/24 dev lan
in_ns client ip link set dev lan0 up
in_ns printer ip link set dev lan up
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
ip netns exec "$(ns printer)" python3 "$work/web.py" >"$work/printer.log" 2>&1 &
pids+=($!)

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=Porta daemon test CA" \
  -keyout "$work/ca.key" -out "$work/ca.pem" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -subj "/CN=gateway" \
  -keyout "$work/gateway.key" -out "$work/gateway.csr" >/dev/null 2>&1
openssl x509 -req -in "$work/gateway.csr" -CA "$work/ca.pem" -CAkey "$work/ca.key" \
  -CAcreateserial -days 1 -extfile <(printf 'subjectAltName=IP:172.31.0.2\n') \
  -out "$work/gateway.crt" >/dev/null 2>&1
openssl rand -hex 24 >"$work/token"
chmod 0600 "$work/token" "$work/ca.key" "$work/gateway.key"

install -d -m 0700 "$work/gateway"
ip netns exec "$(ns gateway)" env PORTA_TOKEN="$(<"$work/token")" PORTA_ADMIN_TOKEN=admin-token-0123456789abcdef \
  "$server_binary" --listen ":$port" --admin-listen 127.0.0.1:9090 \
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
for _ in $(seq 1 60); do
  in_ns gateway curl -fsS --max-time 2 http://127.0.0.1:9090/readyz >/dev/null 2>&1 && break
  sleep 0.5
done

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
install -d -m 0755 "$work/run"
ip netns exec "$(ns client)" env PATH="$work/bin:$PATH" \
  "$client_binary" --daemon --control-socket "$socket" --control-group "$control_group" \
  --profiles "$work/client/profiles.json" --network-state "$work/client/network-state.json" \
  --identity "$work/client/identity.json" --interface porta-ci0 --ca "$work/ca.pem" \
  >"$work/daemon.log" 2>&1 &
daemon_pid=$!
for _ in $(seq 1 50); do
  [[ -S $socket ]] && break
  sleep 0.1
done
[[ -S $socket ]] || { echo "the daemon did not create its control socket" >&2; exit 1; }
[[ $(stat -c '%a %U %G' "$socket") == "660 root $control_group" ]] || {
  echo "control socket has $(stat -c '%a %U %G' "$socket")" >&2
  exit 1
}

cat >"$work/control.py" <<'PY'
import json
import socket
import sys

path, request = sys.argv[1], json.loads(sys.argv[2])
connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
connection.connect(path)
connection.sendall(json.dumps(request).encode() + b"\n")
response = json.loads(connection.makefile().readline())
if "error" in response:
    print(response["error"], file=sys.stderr)
    sys.exit(3)
print(json.dumps(response["snapshot"]))
PY
control() { python3 "$work/control.py" "$socket" "$1"; }
field() { python3 -c "import json, sys; print(json.load(sys.stdin)$1)"; }
wait_for() {
  local expression=$1 what=$2
  for _ in $(seq 1 80); do
    if control '{"command":"snapshot"}' | python3 -c "import json, sys; s = json.load(sys.stdin); sys.exit(0 if ($expression) else 1)"; then
      return 0
    fi
    sleep 0.25
  done
  echo "the daemon did not report $what:" >&2
  control '{"command":"snapshot"}' >&2
  return 1
}
seen() { in_ns client curl -fsS --max-time 2 "http://$web:8080/" 2>/dev/null || true; }
printer() { in_ns client curl -fsS --max-time 2 "http://192.168.77.10:8080/" 2>/dev/null || true; }

# Only root and the control group may use the socket.
if setpriv --reuid=nobody --regid="$other_group" --clear-groups python3 "$work/control.py" "$socket" '{"command":"snapshot"}' >/dev/null 2>&1; then
  echo "a user outside the control group used the control socket" >&2
  exit 1
fi
setpriv --reuid=nobody --regid="$control_group" --clear-groups python3 "$work/control.py" "$socket" '{"command":"snapshot"}' >/dev/null
echo "only root and the control group reach the control socket"

[[ $(control '{"command":"snapshot"}' | field '["platform"]') == linux ]]
profile=$(control "{\"command\":\"save_profile\",\"input\":{\"name\":\"Office\",\"serverUrl\":\"https://172.31.0.2:$port\",\"transport\":\"auto\",\"token\":\"$(<"$work/token")\"}}")
id=$(field '["profiles"][0]["id"]' <<<"$profile")
[[ $(stat -c %a "$work/client/profiles.json") == 600 ]]
control "{\"command\":\"connect\",\"id\":\"$id\"}" >/dev/null
wait_for 's["connected"] and s["status"] == "Connected" and s["address"].startswith("10.66.0.")' "a connection"
[[ $(seen) == 172.31.9.1 ]] || { echo "traffic does not use the tunnel" >&2; exit 1; }
snapshot=$(control '{"command":"snapshot"}')
[[ $(field '["transport"]' <<<"$snapshot") == h3 ]]
[[ $(field '["profiles"][0]["active"]' <<<"$snapshot") == True ]]
if control "{\"command\":\"delete_profile\",\"id\":\"$id\"}" 2>/dev/null; then
  echo "the active profile was deleted" >&2
  exit 1
fi
[[ -z $(printer) ]] || { echo "the full tunnel let local traffic out" >&2; exit 1; }
echo "the daemon connects a saved profile and reports the tunnel"

control '{"command":"disconnect"}' >/dev/null
wait_for 'not s["running"] and s["status"] == "Disconnected"' "a disconnection"
[[ ! -e $work/client/network-state.json ]] || { echo "disconnecting left network state behind" >&2; exit 1; }
if in_ns client ip link show dev porta-ci0 >/dev/null 2>&1; then
  echo "disconnecting left the TUN interface behind" >&2
  exit 1
fi
echo "disconnecting restores the network"

# Allowing the local network keeps the printer reachable beside the tunnel.
control "{\"command\":\"save_profile\",\"input\":{\"id\":\"$id\",\"name\":\"Office\",\"serverUrl\":\"https://172.31.0.2:$port\",\"transport\":\"auto\",\"allowLan\":true}}" >/dev/null
[[ $(control '{"command":"snapshot"}' | field '["profiles"][0]["allowLan"]') == True ]]
control "{\"command\":\"connect\",\"id\":\"$id\"}" >/dev/null
wait_for 's["connected"] and s["status"] == "Connected"' "a connection with local network access"
[[ $(printer) == 192.168.77.1 ]] || { echo "the local printer is unreachable with local network access" >&2; exit 1; }
[[ $(seen) == 172.31.9.1 ]] || { echo "Internet traffic left the tunnel with local network access" >&2; exit 1; }
if in_ns client nft list ruleset | grep -q "192.168.77.0/24.*accept"; then :; else
  echo "the leak protection lacks the local network rule" >&2
  exit 1
fi
control '{"command":"disconnect"}' >/dev/null
wait_for 'not s["running"] and s["status"] == "Disconnected"' "a disconnection"
echo "a profile that allows the local network reaches it beside a full tunnel"

wrong=$(control "{\"command\":\"save_profile\",\"input\":{\"name\":\"Wrong\",\"serverUrl\":\"https://172.31.0.2:$port\",\"token\":\"wrong-token-0123456789abcdef\"}}")
wrong_id=$(python3 -c 'import json, sys; print(next(p["id"] for p in json.load(sys.stdin)["profiles"] if p["name"] == "Wrong"))' <<<"$wrong")
control "{\"command\":\"connect\",\"id\":\"$wrong_id\"}" >/dev/null
wait_for 'not s["running"] and s["status"] == "Connection error"' "the authentication failure"
echo "a rejected token is reported as a connection error"

kill "$daemon_pid"
wait "$daemon_pid" 2>/dev/null || true
daemon_pid=
[[ ! -e $socket ]] || { echo "the daemon left its control socket behind" >&2; exit 1; }
echo "client daemon test passed"
