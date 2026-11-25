#!/usr/bin/env bash
# End-to-end test of TPM-backed device keys, with a software TPM (swtpm)
# whose endorsement key certificate a local CA issues.
#
#   client (swtpm on its loopback) --west/east-- gateway --egress-- web (192.0.2.80)
#
# The gateway trusts the local CA as a TPM vendor and its account requires
# hardware-protected devices. A client with its key in the TPM is enrolled,
# refused, proves its key by credential activation and connects; later runs
# connect at once. A client with a key of its own stays refused.
#
# Usage: sudo scripts/test-tpm-attestation.sh [path-to-porta-server] [path-to-porta-client]
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "run with sudo" >&2; exit 2; }
repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
server_binary=$(realpath "${1:-$repository_root/rust/target/debug/porta-server}")
client_binary=$(realpath "${2:-$repository_root/rust/target/debug/porta-client}")
for binary in "$server_binary" "$client_binary"; do
  [[ -x $binary ]] || { echo "missing executable: $binary (build the workspace first)" >&2; exit 2; }
done
for command in curl ip nft openssl python3 swtpm swtpm_setup swtpm_localca; do
  command -v "$command" >/dev/null || { echo "missing required command: $command" >&2; exit 2; }
done

port=8443
tpm_port=2321
suffix=$$
work=$(mktemp -d /tmp/porta-tpm.XXXXXX)
chmod 0755 "$work"
pids=()
gateway_pid=
client_pid=
web=192.0.2.80
admin_token=admin-token-0123456789abcdef

ns() { printf 'pt%s-%s' "$suffix" "$1"; }
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
  if [[ -f $work/swtpm.pid ]]; then
    kill "$(<"$work/swtpm.pid")" 2>/dev/null || true
  fi
  for node in client gateway web; do
    ip netns delete "$(ns "$node")" 2>/dev/null || true
    rm -rf "/etc/netns/$(ns "$node")"
  done
  if [[ $status -ne 0 ]]; then
    echo "TPM attestation test failed; logs:" >&2
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

# A software TPM with an endorsement key certificate from a local CA.
install -d "$work/tpm" "$work/localca"
printf 'statedir = %s\nsigningkey = %s/signkey.pem\nissuercert = %s/issuercert.pem\ncertserial = %s/certserial\n' \
  "$work/localca" "$work/localca" "$work/localca" "$work/localca" >"$work/swtpm-localca.conf"
: >"$work/swtpm-localca.options"
printf 'create_certs_tool = %s\ncreate_certs_tool_config = %s\ncreate_certs_tool_options = %s\n' \
  "$(command -v swtpm_localca)" "$work/swtpm-localca.conf" "$work/swtpm-localca.options" >"$work/swtpm_setup.conf"
swtpm_setup --tpm2 --tpm-state "$work/tpm" --create-ek-cert --overwrite \
  --config "$work/swtpm_setup.conf" --logfile "$work/swtpm-setup.log" >/dev/null
in_ns client swtpm socket --tpmstate "dir=$work/tpm" --tpm2 \
  --server "type=tcp,port=$tpm_port,bindaddr=127.0.0.1" --ctrl "type=tcp,port=$((tpm_port + 1)),bindaddr=127.0.0.1" \
  --flags not-need-init,startup-clear --daemon --pid "file=$work/swtpm.pid" --log "file=$work/swtpm.log"
install -d -m 0755 "$work/tpm-ca"
cp "$work/localca/swtpm-localca-rootca-cert.pem" "$work/localca/issuercert.pem" "$work/tpm-ca/"

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=Porta TPM test CA" \
  -keyout "$work/ca.key" -out "$work/ca.pem" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -subj "/CN=gateway" \
  -keyout "$work/gateway.key" -out "$work/gateway.csr" >/dev/null 2>&1
openssl x509 -req -in "$work/gateway.csr" -CA "$work/ca.pem" -CAkey "$work/ca.key" \
  -CAcreateserial -days 1 -extfile <(printf 'subjectAltName=IP:172.31.0.2\n') \
  -out "$work/gateway.crt" >/dev/null 2>&1
openssl rand -hex 24 >"$work/token"
chmod 0600 "$work/token" "$work/ca.key" "$work/gateway.key"

install -d -m 0700 "$work/gateway"
ip netns exec "$(ns gateway)" env PORTA_TOKEN="$(<"$work/token")" PORTA_ADMIN_TOKEN="$admin_token" \
  "$server_binary" --listen ":$port" --admin-listen 127.0.0.1:9090 \
  --tls-cert "$work/gateway.crt" --tls-key "$work/gateway.key" \
  --client-registry "$work/gateway/clients.json" --lease-state "$work/gateway/leases.json" \
  --interface porta0 --egress-interface egress --pool 10.66.0.0/24 --dns 192.0.2.53 \
  --tpm-ca-dir "$work/tpm-ca" >"$work/gateway.log" 2>&1 &
gateway_pid=$!
for _ in $(seq 1 100); do
  in_ns gateway ip link show dev porta0 >/dev/null 2>&1 && break
  sleep 0.1
done
in_ns gateway env PORTA_RUNTIME_DIRECTORY="$work/runtime" \
  "$repository_root/scripts/server-up.sh" porta0 10.66.0.1/24 10.66.0.0/24 egress "$port" \
  >>"$work/gateway.log" 2>&1
for _ in $(seq 1 60); do
  in_ns gateway curl -fsS --max-time 2 http://127.0.0.1:9090/readyz >/dev/null 2>&1 && break
  sleep 0.5
done
grep -q "TPM device keys are verified" "$work/gateway.log" || { echo "the gateway did not load the TPM CAs" >&2; exit 1; }

api() {
  in_ns gateway curl -fsS --max-time 10 -H "Authorization: Bearer $admin_token" \
    -H "Content-Type: application/json" "$@"
}
json() { python3 -c "import json, sys; print($1)"; }
account=$(api http://127.0.0.1:9090/api/clients | json 'json.load(sys.stdin)["clients"][0]["id"]')
api -X PUT --data '{"policy":"open","require_hardware":true}' \
  "http://127.0.0.1:9090/api/clients/$account/enrollment" >/dev/null
echo "the account requires hardware-protected devices"

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

client() {
  local identity=$1
  shift
  exec ip netns exec "$(ns client)" env PORTA_TOKEN="$(<"$work/token")" PATH="$work/bin:$PATH" \
    PORTA_TPM_TCP="127.0.0.1:$tpm_port" \
    "$client_binary" --server "https://172.31.0.2:$port" --ca "$work/ca.pem" \
    --identity "$work/client/$identity.json" --network-state "$work/network-state.json" \
    --interface porta-ci0 --reconnect=false "$@"
}
seen() { in_ns client curl -fsS --max-time 5 "http://$web:8080/" 2>/dev/null || true; }
run_until_connected() {
  local log=$1
  shift
  client tpm "$@" >"$work/$log.log" 2>&1 &
  client_pid=$!
  for _ in $(seq 1 60); do
    grep -qs "connected address=" "$work/$log.log" && return 0
    kill -0 "$client_pid" 2>/dev/null || { echo "the client exited:" >&2; cat "$work/$log.log" >&2; exit 1; }
    sleep 1
  done
  echo "the client did not connect" >&2
  exit 1
}
stop_client() {
  kill -INT "$client_pid"
  wait "$client_pid" 2>/dev/null || true
  client_pid=
}

# A key of the device's own is refused.
if (client software) >"$work/software.log" 2>&1; then
  echo "a software key connected to an account that requires hardware" >&2
  exit 1
fi
grep -q "secure hardware" "$work/software.log" || { echo "the software key was refused without saying why" >&2; exit 1; }
echo "a device key outside the TPM is refused"

run_until_connected first --hardware-key
grep -q "verified that the device key is in the" "$work/first.log" || { echo "the client did not prove its TPM key" >&2; exit 1; }
[[ $(seen) == 172.31.9.1 ]] || { echo "traffic does not use the tunnel" >&2; exit 1; }
stop_client
devices=$(api http://127.0.0.1:9090/api/clients)
python3 - "$devices" <<'PY'
import json, sys
clients = json.loads(sys.argv[1])["clients"]
devices = clients[0]["devices"]
verified = [d for d in devices if d.get("hardware")]
assert len(verified) == 1, devices
assert verified[0]["hardware"]["platform"] == "tpm" and verified[0]["hardware"]["level"] == "tpm", verified
assert clients[0]["require_hardware"] is True
PY
grep -q '"version": 2' "$work/client/tpm.json" || { echo "the identity file does not hold a TPM key" >&2; exit 1; }
echo "a TPM key proves itself by credential activation and connects"

run_until_connected second
if grep -q "proving to the gateway" "$work/second.log"; then
  echo "a verified key was asked to prove itself again" >&2
  exit 1
fi
stop_client
echo "a verified TPM key connects at once on later runs"
echo "TPM attestation test passed"
