#!/usr/bin/env bash
# End-to-end test of the C interface the macOS and iOS apps use, with
# network namespaces and the real gateway.
#
#   probe --west/east-- gateway --egress-- web (192.0.2.80)
#
# A C program linked against libporta.a creates a file identity, connects
# with a device proof, reads the session's network settings, pings the web
# host through the tunnel, and cancels the session. A wrong token is
# reported as a failure.
#
# Usage: sudo scripts/test-apple-ffi.sh [path-to-porta-server] [path-to-ffi-probe]
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "run with sudo" >&2; exit 2; }
repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
server_binary=$(realpath "${1:-$repository_root/rust/target/debug/porta-server}")
probe_binary=$(realpath "${2:-$repository_root/bin/porta-ffi-probe}")
for binary in "$server_binary" "$probe_binary"; do
  [[ -x $binary ]] || { echo "missing executable: $binary (make test-apple-ffi builds the probe)" >&2; exit 2; }
done
for command in curl ip nft openssl python3; do
  command -v "$command" >/dev/null || { echo "missing required command: $command" >&2; exit 2; }
done

port=8443
suffix=$$
work=$(mktemp -d /tmp/porta-ffi.XXXXXX)
chmod 0700 "$work"
pids=()
gateway_pid=
admin_token=admin-token-0123456789abcdef
web=192.0.2.80

ns() { printf 'pa%s-%s' "$suffix" "$1"; }
in_ns() { local name=$1; shift; ip netns exec "$(ns "$name")" "$@"; }

cleanup() {
  local status=$?
  trap - EXIT
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
  for node in probe gateway web; do
    ip netns delete "$(ns "$node")" 2>/dev/null || true
  done
  if [[ $status -ne 0 ]]; then
    echo "Apple FFI test failed; logs:" >&2
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

for node in probe gateway web; do
  ip netns add "$(ns "$node")"
  in_ns "$node" ip link set lo up
done
ip link add west netns "$(ns probe)" type veth peer name east netns "$(ns gateway)"
ip link add egress netns "$(ns gateway)" type veth peer name ingress netns "$(ns web)"
in_ns probe ip address add 172.31.0.1/30 dev west
in_ns gateway ip address add 172.31.0.2/30 dev east
in_ns gateway ip address add 172.31.9.1/30 dev egress
in_ns web ip address add 172.31.9.2/30 dev ingress
in_ns web ip address add "$web/32" dev lo
for pair in "probe west" "gateway east" "gateway egress" "web ingress"; do
  read -r node interface <<<"$pair"
  in_ns "$node" ip link set dev "$interface" up
done
in_ns gateway ip route add default via 172.31.9.2

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=Porta FFI test CA" \
  -keyout "$work/ca.key" -out "$work/ca.pem" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -subj "/CN=gateway" \
  -keyout "$work/gateway.key" -out "$work/gateway.csr" >/dev/null 2>&1
openssl x509 -req -in "$work/gateway.csr" -CA "$work/ca.pem" -CAkey "$work/ca.key" \
  -CAcreateserial -days 1 -extfile <(printf 'subjectAltName=IP:172.31.0.2\n') \
  -out "$work/gateway.crt" >/dev/null 2>&1
openssl rand -hex 24 >"$work/token"

install -d -m 0700 "$work/gateway"
ip netns exec "$(ns gateway)" env PORTA_TOKEN="$(<"$work/token")" PORTA_ADMIN_TOKEN="$admin_token" \
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
install -d -m 0700 "$work/probe"
probe() {
  local token=$1
  in_ns probe env PORTA_TOKEN="$token" "$probe_binary" "https://172.31.0.2:$port" 172.31.0.2 \
    "$work/ca.pem" "$work/probe/identity.json" "$web"
}
probe "$(<"$work/token")" >"$work/probe.log" 2>&1 || { cat "$work/probe.log" >&2; exit 1; }
grep -q "^device d-" "$work/probe.log"
grep -q '^info {"account":' "$work/probe.log" || grep -q '^info {' "$work/probe.log"
grep -q '"address":"10.66.0.[0-9]*/32"' "$work/probe.log"
grep -q '"fullTunnel":true' "$work/probe.log"
grep -q "echo reply from $web" "$work/probe.log"
grep -q "^after cancel -" "$work/probe.log"
echo "the C interface connects with a device proof, reports settings and carries traffic"

device=$(sed -n 's/^device //p' "$work/probe.log")
in_ns gateway curl -fsS --max-time 10 -H "Authorization: Bearer $admin_token" http://127.0.0.1:9090/api/clients |
  python3 -c "import json, sys; ids = [d['id'] for d in json.load(sys.stdin)['clients'][0]['devices']]; sys.exit(0 if '$device' in ids else 1)" || {
  echo "the gateway did not enroll the probe's device $device" >&2
  exit 1
}
if probe wrong-token-0123456789abcdef >"$work/wrong.log" 2>&1; then
  echo "a wrong token connected" >&2
  exit 1
fi
grep -q "^connect (status -2)" "$work/wrong.log" || { cat "$work/wrong.log" >&2; exit 1; }
echo "Apple FFI test passed"
