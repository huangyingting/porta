#!/usr/bin/env bash
# End-to-end test of the shipped systemd sandbox for porta.service.
#
#   client -> gateway 1 (relay service) -> gateway 2 (exit service) -> web
#
# Each gateway runs under systemd with every [Service] hardening setting of
# deploy/porta.service, an unprivileged user, its ambient capabilities, and
# the "!"-prefixed network helpers, inside a network namespace. The test
# checks that the daemons hold only their ambient capabilities, own their
# state, create their TUNs, relay traffic to the exit, and that the root
# helpers both configure and clean up the firewall.
#
# The shipped unit's User=porta is replaced by the unprivileged nobody user
# so the test creates no accounts on the host.
#
# Usage: sudo scripts/test-service-user.sh [path-to-porta-server] [path-to-porta-client]
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "run with sudo" >&2; exit 2; }
repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
server_binary=$(realpath "${1:-$repository_root/rust/target/debug/porta-server}")
client_binary=$(realpath "${2:-$repository_root/rust/target/debug/porta-client}")
for binary in "$server_binary" "$client_binary"; do
  [[ -x $binary ]] || { echo "missing executable: $binary (build the workspace first)" >&2; exit 2; }
done
for command in curl ip nft openssl python3 systemd-run systemctl; do
  command -v "$command" >/dev/null || { echo "missing required command: $command" >&2; exit 2; }
done
[[ -d /run/systemd/system ]] || { echo "systemd is not running" >&2; exit 2; }

unit_file=$repository_root/deploy/porta.service
service_user=nobody
service_group=$(id -gn "$service_user")
port=8443
suffix=$$
prefix=porta-e2e-$suffix
files=/var/lib/$prefix-files
client_pid=

ns() { printf 'pu%s-%s' "$suffix" "$1"; }
in_ns() { local name=$1; shift; ip netns exec "$(ns "$name")" "$@"; }
link_address() { printf '172.31.%s.%s' "$1" "$2"; }
unit_name() { printf '%s-gw%s.service' "$prefix" "$1"; }

cleanup() {
  local status=$?
  trap - EXIT
  if [[ -n $client_pid ]]; then
    kill -INT "$client_pid" 2>/dev/null || true
    wait "$client_pid" 2>/dev/null || true
  fi
  if [[ $status -ne 0 ]]; then
    echo "service user test failed; logs:" >&2
    for gateway in 1 2; do
      echo "==> $(unit_name "$gateway")" >&2
      journalctl -u "$(unit_name "$gateway")" -n 40 --no-pager -o cat >&2 || true
    done
    [[ -f $files/client.log ]] && { echo "==> client" >&2; tail -n 40 "$files/client.log" >&2; }
  fi
  for gateway in 1 2; do
    systemctl stop "$(unit_name "$gateway")" 2>/dev/null || true
    systemctl reset-failed "$(unit_name "$gateway")" 2>/dev/null || true
    rm -rf "/var/lib/$prefix-gw$gateway" "/run/$prefix-gw$gateway"
  done
  for node in client 1 2 web; do
    ip netns delete "$(ns "$node")" 2>/dev/null || true
    rm -rf "/etc/netns/$(ns "$node")"
  done
  rm -rf "$files"
  exit "$status"
}
trap cleanup EXIT

grep -qx 'User=porta' "$unit_file" || { echo "porta.service does not run as the porta user" >&2; exit 1; }
grep -qx 'ReadWritePaths=/run/porta' "$unit_file" || {
  echo "porta.service does not expose the root-only helper state directory" >&2
  exit 1
}
grep -q '^ExecStartPost=!' "$unit_file" && grep -q '^ExecStopPost=!' "$unit_file" || {
  echo "porta.service network helpers do not run with elevated credentials" >&2
  exit 1
}
# Hardening properties copied from the shipped unit; per-test paths,
# commands, and identity are supplied below.
sandbox=()
while IFS= read -r line; do
  case $line in
    ''|'#'*|'['*) continue ;;
    Type=*|User=*|Group=*|EnvironmentFile=*|Exec*|Restart*|StateDirectory*|ReadWritePaths=*) continue ;;
  esac
  sandbox+=(--property "$line")
done < <(sed -n '/^\[Service\]/,/^\[/p' "$unit_file")

# Nodes in a line: client, gateway 1, gateway 2, web. Link k joins node k
# ("east") to node k+1 ("west") on 172.31.k.0/30.
nodes=(client 1 2 web)
for node in "${nodes[@]}"; do
  ip netns add "$(ns "$node")"
  in_ns "$node" ip link set lo up
done
for k in 0 1 2; do
  left=${nodes[$k]}
  right=${nodes[$((k + 1))]}
  ip link add east netns "$(ns "$left")" type veth peer name west netns "$(ns "$right")"
  in_ns "$left" ip address add "$(link_address "$k" 1)/30" dev east
  in_ns "$right" ip address add "$(link_address "$k" 2)/30" dev west
  in_ns "$left" ip link set east up
  in_ns "$right" ip link set west up
  in_ns "$left" ip route add default via "$(link_address "$k" 2)"
done
web_address=$(link_address 2 2)
exit_address=$(link_address 2 1)
# The web server reports the source address it sees.
install -d -m 0755 "$files" "$files/bin" "$files/libexec"
cat >"$files/web.py" <<'PY'
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
ip netns exec "$(ns web)" python3 "$files/web.py" >"$files/web.log" 2>&1 &
web_pid=$!

# The sandbox hides /home and /tmp, so the services run copies.
install -m 0755 "$server_binary" "$files/bin/porta-server"
install -m 0755 "$repository_root/scripts/server-up.sh" "$repository_root/scripts/server-down.sh" \
  "$repository_root/scripts/sync-cert.sh" "$files/libexec/"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=Porta service test CA" \
  -keyout "$files/ca.key" -out "$files/ca.pem" >/dev/null 2>&1
chmod 0644 "$files/ca.pem"
for gateway in 1 2; do
  directory=$files/gw$gateway
  install -d -m 0700 "$directory"
  public=$(link_address "$((gateway - 1))" 2)
  openssl req -newkey rsa:2048 -nodes -subj "/CN=$public" \
    -keyout "$directory/source.key" -out "$directory/server.csr" >/dev/null 2>&1
  openssl x509 -req -in "$directory/server.csr" -CA "$files/ca.pem" -CAkey "$files/ca.key" \
    -CAcreateserial -days 1 -extfile <(printf 'subjectAltName=IP:%s\n' "$public") \
    -out "$directory/source.crt" >/dev/null 2>&1
  # Publish the key exactly as porta-cert-sync.service does.
  "$files/libexec/sync-cert.sh" "$directory/source.crt" "$directory/source.key" \
    "$files/tls-$gateway" "$service_group"
  openssl rand -hex 24 >"$directory/token"
done
chmod 0755 "$files"

start_gateway() {
  local gateway=$1
  local directory=$files/gw$gateway
  local state=/var/lib/$prefix-gw$gateway
  # Root-only helper state, as deploy/porta-tmpfiles.conf creates /run/porta.
  local runtime=/run/$prefix-gw$gateway
  install -d -m 0700 "$runtime"
  local arguments=(
    --listen ":$port" --admin-listen 127.0.0.1:9090
    --tls-cert "$files/tls-$gateway/server.crt" --tls-key "$files/tls-$gateway/server.key"
    --client-registry "$state/clients.json" --lease-state "$state/leases.json"
    --usage-state "$state/usage.json"
    --interface porta0 --egress-interface east --pool 10.66.0.0/24 --dns "$web_address"
  )
  local helper_options=
  {
    printf 'PORTA_TOKEN=%s\n' "$(<"$directory/token")"
    printf 'PORTA_ADMIN_TOKEN=admin-token-0123456789abcdef\n'
    if ((gateway == 1)); then
      printf 'PORTA_UPSTREAM_TOKEN=%s\n' "$(<"$files/gw2/token")"
    fi
  } >"$directory/env"
  chmod 0600 "$directory/env"
  if ((gateway == 1)); then
    arguments+=(
      --upstream "https://$(link_address 1 2):$port" --upstream-ca "$files/ca.pem"
      --upstream-identity "$state/upstream-identity.json"
    )
    helper_options=" --upstream-interface porta-up0"
  fi
  systemd-run --quiet --unit "$(unit_name "$gateway")" \
    --property "NetworkNamespacePath=/run/netns/$(ns "$gateway")" \
    --property "User=$service_user" --property "Group=$service_group" \
    --property "EnvironmentFile=$directory/env" \
    --property "Environment=PORTA_RUNTIME_DIRECTORY=$runtime" \
    --property "StateDirectory=$prefix-gw$gateway" \
    --property "ReadWritePaths=$runtime" \
    --property "ExecStartPost=!/bin/bash -c 'for i in \$(seq 1 50); do ip link show dev porta0 >/dev/null 2>&1 && exec $files/libexec/server-up.sh porta0 10.66.0.1/24 10.66.0.0/24 east $port$helper_options; sleep 0.1; done; exit 1'" \
    --property "ExecStopPost=!$files/libexec/server-down.sh porta0 east" \
    "${sandbox[@]}" \
    "$files/bin/porta-server" "${arguments[@]}"
  for _ in $(seq 1 60); do
    if in_ns "$gateway" curl -fsS --max-time 5 http://127.0.0.1:9090/readyz >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  in_ns "$gateway" curl -sS --max-time 5 http://127.0.0.1:9090/readyz >&2 || true
  echo "gateway $gateway did not become ready" >&2
  return 1
}

start_gateway 2
start_gateway 1
echo "relay and exit gateways are ready under systemd"

for gateway in 1 2; do
  unit=$(unit_name "$gateway")
  pid=$(systemctl show --property MainPID --value "$unit")
  user=$(ps -o user= -p "$pid" | tr -d ' ')
  [[ $user == "$service_user" ]] || { echo "gateway $gateway runs as $user" >&2; exit 1; }
  effective=$(sed -n 's/^CapEff:\t//p' "/proc/$pid/status")
  # CAP_NET_ADMIN only: the bounding set's CAP_DAC_OVERRIDE is for the helpers.
  [[ $effective == 0000000000001000 ]] || {
    echo "gateway $gateway has effective capabilities $effective" >&2
    exit 1
  }
  owner=$(stat -c %U "/var/lib/$prefix-gw$gateway/clients.json")
  [[ $owner == "$service_user" ]] || { echo "gateway $gateway state is owned by $owner" >&2; exit 1; }
  [[ -f /run/$prefix-gw$gateway/ip-forward-porta0 && $(stat -c %U "/run/$prefix-gw$gateway/ip-forward-porta0") == root ]] || {
    echo "gateway $gateway helpers did not record root-owned state" >&2
    exit 1
  }
done
in_ns 1 ip link show dev porta-up0 >/dev/null
echo "daemons run as $service_user with only CAP_NET_ADMIN and own their state and TUNs"

install -d "$files/client-bin"
cat >"$files/client-bin/resolvectl" <<'EOF'
#!/usr/bin/env bash
case "${1:-}" in
  status|revert|default-route) exit 0 ;;
  dns|domain) [[ $# == 2 ]] && printf 'Link 2 (%s):\n' "$2"; exit 0 ;;
  *) exit 2 ;;
esac
EOF
chmod 0755 "$files/client-bin/resolvectl"
install -d "/etc/netns/$(ns client)"
printf 'nameserver 127.0.0.53\n' >"/etc/netns/$(ns client)/resolv.conf"
install -d -m 0700 "$files/client"
ip netns exec "$(ns client)" env PORTA_TOKEN="$(<"$files/gw1/token")" PATH="$files/client-bin:$PATH" \
  "$client_binary" --server "https://$(link_address 0 2):$port" --ca "$files/ca.pem" \
  --identity "$files/client/identity.json" --network-state "$files/client/network-state.json" \
  --interface porta-ci0 >"$files/client.log" 2>&1 &
client_pid=$!
for _ in $(seq 1 60); do
  grep -qs "connected address=" "$files/client.log" && break
  kill -0 "$client_pid" 2>/dev/null || { echo "client exited" >&2; exit 1; }
  sleep 1
done
grep -qs "connected address=" "$files/client.log" || { echo "client did not connect" >&2; exit 1; }
seen=$(in_ns client curl -fsS --max-time 10 "http://$web_address:8080/")
[[ $seen == "$exit_address" ]] || { echo "web server saw $seen, want exit $exit_address" >&2; exit 1; }
echo "client traffic is relayed through both sandboxed gateways"

kill -INT "$client_pid"
wait "$client_pid" 2>/dev/null || true
client_pid=
for gateway in 1 2; do
  systemctl stop "$(unit_name "$gateway")"
  if in_ns "$gateway" nft list tables | grep -q porta; then
    echo "gateway $gateway helpers left Porta firewall tables behind" >&2
    exit 1
  fi
done
kill "$web_pid" 2>/dev/null || true
echo "stopping the services ran the root cleanup helpers"
echo "service user test passed"
