#!/usr/bin/env bash
set -euo pipefail

if [[ ${1:-} == --namespace ]]; then
  repository_root=$2
  work=$3
  server=$4
  gateway=$5
  transports=$6
  client=$7
  interface=porta-ci0
  state_path=$work/network-state.json
  identity_path=$work/client-identity.json
  token_file=$work/client-token
  fake_bin=$work/bin
  client_pid=

  stop_client() {
    if [[ -z $client_pid ]]; then
      return
    fi
    if kill -0 "$client_pid" 2>/dev/null; then
      kill -INT "$client_pid"
      for _ in $(seq 1 30); do
        if ! kill -0 "$client_pid" 2>/dev/null; then
          break
        fi
        sleep 1
      done
    fi
    if kill -0 "$client_pid" 2>/dev/null; then
      kill -TERM "$client_pid"
    fi
    wait "$client_pid" 2>/dev/null || true
    client_pid=
  }

  cleanup() {
    status=$?
    trap - EXIT
    stop_client
    if [[ -e $state_path ]]; then
      PORTA_TOKEN="$(<"$token_file")" PATH="$fake_bin:/usr/sbin:/usr/bin:/sbin:/bin" \
        "$client" --cleanup-network --network-state "$state_path" \
        >>"$work/artifacts/cleanup.log" 2>&1 || status=1
    fi
    exit "$status"
  }
  trap cleanup EXIT

  mkdir -p "$fake_bin"
  cat >"$fake_bin/resolvectl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
case "${1:-}" in
  status|revert) exit 0 ;;
  dns|domain)
    if [[ $# == 2 ]]; then
      printf 'Link 2 (%s):\n' "$2"
    fi
    ;;
  default-route) ;;
  *) exit 2 ;;
esac
EOF
  chmod 0755 "$fake_bin/resolvectl"
  export PATH="$fake_bin:/usr/sbin:/usr/bin:/sbin:/bin"

  if ping -n -c 1 -W 1 "$gateway" >/dev/null 2>&1; then
    echo "private Porta gateway is reachable before the VPN starts" >&2
    exit 1
  fi

  mkdir -p "$work/artifacts"
  for transport in $transports; do
    case "$transport" in
      h2|h3) ;;
      *)
        echo "unsupported E2E transport: $transport" >&2
        exit 2
        ;;
    esac
    log=$work/artifacts/$transport.log
    rm -f "$state_path" "$state_path.lock" "$log"
    PORTA_TOKEN="$(<"$token_file")" "$client" \
      --server "$server" \
      --transport "$transport" \
      --interface "$interface" \
      --identity "$identity_path" \
      --network-state "$state_path" \
      --reconnect=false >"$log" 2>&1 &
    client_pid=$!

    connected=false
    for _ in $(seq 1 90); do
      if grep -q "connected address=.* transport=$transport " "$log"; then
        connected=true
        break
      fi
      if ! kill -0 "$client_pid" 2>/dev/null; then
        cat "$log" >&2
        echo "Porta client exited before the $transport tunnel connected" >&2
        exit 1
      fi
      sleep 1
    done
    if [[ $connected != true ]]; then
      cat "$log" >&2
      echo "Porta client did not establish the $transport tunnel" >&2
      exit 1
    fi

    route=$(ip -4 route get "$gateway")
    if [[ $route != *"dev $interface"* ]]; then
      printf 'private gateway route did not use %s: %s\n' "$interface" "$route" >&2
      exit 1
    fi
    owned_routes=$(ip -4 route show table main proto 186)
    for prefix in 0.0.0.0/1 128.0.0.0/1; do
      if ! awk -v prefix="$prefix" -v interface="$interface" '
        $1 == prefix {
          for (field = 1; field < NF; field++) {
            if ($field == "dev" && $(field + 1) == interface) {
              found = 1
            }
          }
        }
        END { exit !found }
      ' <<<"$owned_routes"; then
        echo "full-tunnel route $prefix is missing for $transport" >&2
        exit 1
      fi
    done
    nft list tables | grep -q '^table inet porta_'
    ping -n -c 3 -W 5 "$gateway" >/dev/null
    ping -n -c 1 -W 5 -M do -s 1200 "$gateway" >/dev/null

    stop_client
    if ip link show dev "$interface" >/dev/null 2>&1; then
      echo "Porta TUN remains after the $transport client stopped" >&2
      exit 1
    fi
    if nft list tables | grep -q '^table inet porta_'; then
      echo "Porta leak-protection table remains after the $transport client stopped" >&2
      exit 1
    fi
    if [[ -e $state_path ]]; then
      echo "Porta network recovery state remains after the $transport client stopped" >&2
      exit 1
    fi
    if ip -4 route show proto 186 | grep -q .; then
      echo "Porta-owned routes remain after the $transport client stopped" >&2
      exit 1
    fi
    if ping -n -c 1 -W 1 "$gateway" >/dev/null 2>&1; then
      echo "private Porta gateway remains reachable after the $transport VPN stopped" >&2
      exit 1
    fi
    printf '%s full-tunnel probe passed\n' "$transport" >>"$work/artifacts/summary.txt"
  done

  trap - EXIT
  exit 0
fi

if [[ ${1:-} == --inside ]]; then
  repository_root=$2
  work=$3
  server=$4
  gateway=$5
  transports=$6
  client=$7
  server_address_override=$8
  namespace=porta-e2e-$$
  host_interface=peh$$
  peer_interface=pen$$
  nat_table=porta_e2e_$$
  forwarding=$(sysctl -n net.ipv4.ip_forward)
  server_host=
  server_address=
  forward_from_namespace=false
  forward_to_namespace=false

  cleanup() {
    status=$?
    trap - EXIT
    if [[ $forward_to_namespace == true ]]; then
      iptables -w -D FORWARD -o "$host_interface" -m conntrack \
        --ctstate ESTABLISHED,RELATED -j ACCEPT >/dev/null 2>&1 || status=1
    fi
    if [[ $forward_from_namespace == true ]]; then
      iptables -w -D FORWARD -i "$host_interface" -j ACCEPT >/dev/null 2>&1 || status=1
    fi
    nft delete table ip "$nat_table" >/dev/null 2>&1 || true
    ip netns delete "$namespace" >/dev/null 2>&1 || true
    ip link delete "$host_interface" >/dev/null 2>&1 || true
    rm -f "/etc/netns/$namespace/resolv.conf" "/etc/netns/$namespace/hosts"
    rmdir "/etc/netns/$namespace" 2>/dev/null || true
    if [[ $forwarding != 1 ]]; then
      sysctl -q -w "net.ipv4.ip_forward=$forwarding"
    fi
    exit "$status"
  }
  trap cleanup EXIT

  ip netns add "$namespace"
  ip link add "$host_interface" type veth peer name "$peer_interface"
  ip link set "$peer_interface" netns "$namespace"
  ip address add 192.0.2.1/30 dev "$host_interface"
  ip link set "$host_interface" up
  ip -n "$namespace" link set lo up
  ip -n "$namespace" address add 192.0.2.2/30 dev "$peer_interface"
  ip -n "$namespace" link set "$peer_interface" up
  ip -n "$namespace" route add default via 192.0.2.1
  server_host=$(python3 - "$server" <<'PY'
import sys
from urllib.parse import urlsplit

host = urlsplit(sys.argv[1]).hostname
if not host:
    raise SystemExit("Porta E2E server URL has no hostname")
print(host)
PY
)
  server_address=$server_address_override
  if [[ -z $server_address ]]; then
    server_address=$(getent ahostsv4 "$server_host" | awk '$2 == "STREAM" { print $1; exit }')
  fi
  if [[ -z $server_address ]]; then
    echo "cannot resolve an IPv4 address for $server_host" >&2
    exit 1
  fi
  sysctl -q -w net.ipv4.ip_forward=1
  nft add table ip "$nat_table"
  nft "add chain ip $nat_table input { type filter hook input priority filter; policy accept; }"
  nft add rule ip "$nat_table" input iifname "$host_interface" ip daddr "$gateway" drop
  nft "add chain ip $nat_table forward { type filter hook forward priority filter; policy accept; }"
  nft add rule ip "$nat_table" forward iifname "$host_interface" ip daddr "$gateway" drop
  nft "add chain ip $nat_table postrouting { type nat hook postrouting priority srcnat; policy accept; }"
  nft add rule ip "$nat_table" postrouting ip saddr 192.0.2.0/30 masquerade
  iptables -w -I FORWARD 1 -i "$host_interface" -j ACCEPT
  forward_from_namespace=true
  iptables -w -I FORWARD 1 -o "$host_interface" -m conntrack \
    --ctstate ESTABLISHED,RELATED -j ACCEPT
  forward_to_namespace=true

  mkdir -p "/etc/netns/$namespace"
  printf 'nameserver 127.0.0.53\n' >"/etc/netns/$namespace/resolv.conf"
  {
    printf '127.0.0.1 localhost\n'
    printf '::1 localhost ip6-localhost ip6-loopback\n'
    printf '%s %s\n' "$server_address" "$server_host"
  } >"/etc/netns/$namespace/hosts"

  ip netns exec "$namespace" "$repository_root/scripts/test-live-vpn.sh" \
    --namespace "$repository_root" "$work" "$server" "$gateway" "$transports" "$client"
  trap - EXIT
  cleanup
fi

for command in awk base64 getent grep install ip iptables nft ping python3 sudo sysctl; do
  command -v "$command" >/dev/null || {
    echo "missing required command: $command" >&2
    exit 1
  }
done

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
server=${PORTA_E2E_SERVER:-https://porta-dev.i-csu.org:8443}
server_address=${PORTA_E2E_SERVER_ADDRESS:-}
gateway=${PORTA_E2E_GATEWAY:-10.66.0.1}
transports=${PORTA_E2E_TRANSPORTS:-"h3 h2"}
token=${PORTA_E2E_TOKEN:-}
identity=${PORTA_E2E_LINUX_IDENTITY_BASE64:-}
artifact_directory=${PORTA_E2E_ARTIFACT_DIR:-}
cargo=${CARGO:-"$HOME/.cargo/bin/cargo"}
client=${PORTA_E2E_CLIENT:-}

python3 - "$server" "$gateway" "$server_address" <<'PY' || exit 2
import ipaddress
import sys
from urllib.parse import urlsplit

server, gateway, server_address = sys.argv[1:]
try:
    origin = urlsplit(server)
    port = origin.port
except ValueError as error:
    raise SystemExit(f"PORTA_E2E_SERVER is invalid: {error}")
if (
    origin.scheme != "https"
    or not origin.hostname
    or origin.username is not None
    or origin.password is not None
    or origin.path not in ("", "/")
    or origin.query
    or origin.fragment
    or (port is not None and not 1 <= port <= 65535)
):
    raise SystemExit("PORTA_E2E_SERVER must be an HTTPS origin")
for name, value in (
    ("PORTA_E2E_GATEWAY", gateway),
    ("PORTA_E2E_SERVER_ADDRESS", server_address),
):
    if not value and name == "PORTA_E2E_SERVER_ADDRESS":
        continue
    try:
        ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError:
        raise SystemExit(f"{name} must be an IPv4 address")
PY
[[ ${#token} -ge 16 ]] || {
  echo "PORTA_E2E_TOKEN is required" >&2
  exit 2
}
[[ -n $identity ]] || {
  echo "PORTA_E2E_LINUX_IDENTITY_BASE64 is required" >&2
  exit 2
}
if [[ -n $artifact_directory ]]; then
  [[ $artifact_directory == /* ]] || {
    echo "PORTA_E2E_ARTIFACT_DIR must be an absolute path" >&2
    exit 2
  }
  [[ ! -e $artifact_directory && ! -L $artifact_directory ]] || {
    echo "PORTA_E2E_ARTIFACT_DIR must not already exist" >&2
    exit 2
  }
  mkdir -m 0700 -- "$artifact_directory"
fi

if [[ -z $client ]]; then
  "$cargo" build --manifest-path "$repository_root/rust/Cargo.toml" \
    --package porta-client-rust --release --locked
  client=$repository_root/rust/target/release/porta-client
fi
client=$(realpath "$client")
[[ -x $client ]] || {
  echo "Porta E2E client is not executable: $client" >&2
  exit 2
}

work=$(mktemp -d "${TMPDIR:-/tmp}/porta-vpn-e2e.XXXXXX")
cleanup() {
  status=$?
  trap - EXIT
  if [[ -n $artifact_directory ]] && sudo -n test -d "$work/artifacts"; then
    for artifact in h2.log h3.log summary.txt cleanup.log; do
      if sudo -n test -f "$work/artifacts/$artifact"; then
        sudo -n install -o "$(id -u)" -g "$(id -g)" -m 0600 \
          "$work/artifacts/$artifact" "$artifact_directory/$artifact" || status=1
      fi
    done
  fi
  if [[ $work == "${TMPDIR:-/tmp}"/porta-vpn-e2e.* ]]; then
    sudo -n rm -rf -- "$work"
  fi
  exit "$status"
}
trap cleanup EXIT

printf '%s' "$token" >"$work/client-token"
printf '%s' "$identity" | base64 --decode >"$work/client-identity.json"
python3 - "$work/client-identity.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    value = json.load(source)
if value.get("version") != 1 or not isinstance(value.get("private_key"), str):
    raise SystemExit("invalid Porta E2E identity")
PY
chmod 0600 "$work/client-token" "$work/client-identity.json"
sudo -n chown -R root:root "$work"
sudo -n "$repository_root/scripts/test-live-vpn.sh" \
  --inside "$repository_root" "$work" "$server" "$gateway" "$transports" "$client" \
  "$server_address"

if sudo -n test -f "$work/artifacts/summary.txt"; then
  sudo -n cat "$work/artifacts/summary.txt"
fi
