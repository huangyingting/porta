#!/usr/bin/env bash
# End-to-end test of standard CONNECT-IP clients using network namespaces,
# the real gateway, and the independent quic-go/connect-ip-go client in
# experiments/masque-interop (bearer token only, no Porta extensions).
#
#   probe --west/east-- gateway --egress-- web (192.0.2.80)
#
# Standard clients are refused until the account allows them; then the
# probe receives an address and routes, with or without asking, and pings
# the gateway and the web host through the tunnel. Turning the setting off
# refuses them again. The gateway also requires a client version from the
# future: native Porta clients are told to update, standard clients are not
# affected.
#
# Usage: sudo scripts/test-standard-masque.sh [path-to-porta-server] [path-to-masque-probe] [path-to-porta-client]
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "run with sudo" >&2; exit 2; }
repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
server_binary=$(realpath "${1:-$repository_root/rust/target/debug/porta-server}")
probe_binary=$(realpath "${2:-$repository_root/bin/masque-probe}")
client_binary=$(realpath "${3:-$repository_root/rust/target/debug/porta-client}")
for binary in "$server_binary" "$probe_binary" "$client_binary"; do
  [[ -x $binary ]] || { echo "missing executable: $binary (make build-masque-probe builds the probe)" >&2; exit 2; }
done
for command in curl ip nft openssl python3; do
  command -v "$command" >/dev/null || { echo "missing required command: $command" >&2; exit 2; }
done

port=8443
suffix=$$
work=$(mktemp -d /tmp/porta-standard.XXXXXX)
chmod 0700 "$work"
pids=()
gateway_pid=
admin_token=admin-token-0123456789abcdef
web=192.0.2.80

ns() { printf 'pm%s-%s' "$suffix" "$1"; }
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
    echo "standard MASQUE test failed; logs:" >&2
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

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=Porta standard test CA" \
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
  --min-client-version 99.0.0 \
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
admin_api() {
  in_ns gateway curl -fsS --max-time 10 -H "Authorization: Bearer $admin_token" \
    -H "Content-Type: application/json" "$@"
}
account=$(admin_api http://127.0.0.1:9090/api/clients | python3 -c 'import json, sys; print(json.load(sys.stdin)["clients"][0]["id"])')
probe() {
  local token=$1
  shift
  in_ns probe env PORTA_TOKEN="$token" "$probe_binary" -proxy "https://172.31.0.2:$port" \
    -ca "$work/ca.pem" -timeout 10s "$@"
}

# A native client older than --min-client-version is told to update.
install -d -m 0700 "$work/native" "$work/bin"
cat >"$work/bin/resolvectl" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
chmod 0755 "$work/bin/resolvectl"
if in_ns probe env PORTA_TOKEN="$(<"$work/token")" PATH="$work/bin:$PATH" timeout 30 \
  "$client_binary" --server "https://172.31.0.2:$port" --ca "$work/ca.pem" \
  --identity "$work/native/identity.json" --network-state "$work/native/network-state.json" \
  --interface porta-ci0 >"$work/native.log" 2>&1; then
  echo "an outdated native client connected" >&2
  exit 1
fi
grep -q "too old for the gateway" "$work/native.log" || {
  echo "the outdated client was not told to update" >&2
  cat "$work/native.log" >&2
  exit 1
}
echo "native clients older than the minimum version are told to update"

if probe "$(<"$work/token")" >"$work/refused.log" 2>&1; then
  echo "a standard client connected before the account allowed it" >&2
  exit 1
fi
grep -q "403" "$work/refused.log" && grep -q "standard-clients-disabled" "$work/refused.log" || {
  echo "the refusal does not name the account setting" >&2
  cat "$work/refused.log" >&2
  exit 1
}
echo "standard clients are refused until the account allows them"

admin_api -X PUT --data '{"policy":"open","standard_clients":true}' \
  "http://127.0.0.1:9090/api/clients/$account/enrollment" >/dev/null
probe "$(<"$work/token")" -ping 10.66.0.1 >"$work/unsolicited.log" 2>&1 || {
  cat "$work/unsolicited.log" >&2
  exit 1
}
grep -q "^address 10.66.0.[0-9]*/32$" "$work/unsolicited.log"
grep -q "^route 0.0.0.0-255.255.255.255 protocol 0$" "$work/unsolicited.log"
grep -q "echo reply from 10.66.0.1" "$work/unsolicited.log"
echo "an unmodified connect-ip-go client receives an address and routes unasked and pings the gateway"

probe "$(<"$work/token")" -request -ping "$web" >"$work/requested.log" 2>&1 || {
  cat "$work/requested.log" >&2
  exit 1
}
grep -q "echo reply from $web" "$work/requested.log"
echo "a client that requests its address reaches the Internet through the gateway"

devices=$(admin_api http://127.0.0.1:9090/api/clients | python3 -c 'import json, sys; print(",".join(d["id"] for d in json.load(sys.stdin)["clients"][0]["devices"]))')
[[ $devices == standard-masque ]] || { echo "unexpected devices: $devices" >&2; exit 1; }
if probe wrong-token-0123456789abcdef >"$work/wrong.log" 2>&1; then
  echo "a wrong token connected" >&2
  exit 1
fi
grep -q "401" "$work/wrong.log"

admin_api -X PUT --data '{"policy":"open","standard_clients":false}' \
  "http://127.0.0.1:9090/api/clients/$account/enrollment" >/dev/null
if probe "$(<"$work/token")" >"$work/disabled.log" 2>&1; then
  echo "a standard client connected after the account stopped allowing them" >&2
  exit 1
fi
echo "standard MASQUE test passed"
