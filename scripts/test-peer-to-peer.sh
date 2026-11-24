#!/usr/bin/env bash
# End-to-end test of direct paths between devices, using network
# namespaces, real NATs and real binaries.
#
#   client A -- NAT A --.
#                        wan -- gateway (--peer-to-peer)
#   client B -- NAT B --'
#
# Both NATs masquerade and only let in replies, like home routers. The
# test checks that the clients learn each other's public addresses from
# the gateway, punch through both NATs and carry their traffic directly;
# that traffic returns to the gateway when the direct path breaks, and the
# path comes back when it heals; and that a device leaving ends its peers'
# paths to it.
#
# Usage: sudo scripts/test-peer-to-peer.sh [path-to-porta-server] [path-to-porta-client]
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
suffix=$$
work=$(mktemp -d /tmp/porta-p2p.XXXXXX)
chmod 0700 "$work"
gateway_pid=
declare -A client_pids=()
admin_token=admin-token-0123456789abcdef
nat_a=198.51.100.6
nat_b=198.51.100.10

ns() { printf 'pp%s-%s' "$suffix" "$1"; }
in_ns() { local name=$1; shift; ip netns exec "$(ns "$name")" "$@"; }

cleanup() {
  local status=$?
  trap - EXIT
  for pid in "${client_pids[@]}"; do
    kill -INT "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  done
  if [[ -n $gateway_pid ]]; then
    kill "$gateway_pid" 2>/dev/null || true
    wait "$gateway_pid" 2>/dev/null || true
  fi
  for node in a b nat-a nat-b wan gateway; do
    ip netns delete "$(ns "$node")" 2>/dev/null || true
    rm -rf "/etc/netns/$(ns "$node")"
  done
  if [[ $status -ne 0 ]]; then
    echo "peer-to-peer test failed; logs:" >&2
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

for node in a b nat-a nat-b wan gateway; do
  ip netns add "$(ns "$node")"
  in_ns "$node" ip link set lo up
done
link() {
  local left=$1 left_name=$2 left_address=$3 right=$4 right_name=$5 right_address=$6
  ip link add "$left_name" netns "$(ns "$left")" type veth peer name "$right_name" netns "$(ns "$right")"
  in_ns "$left" ip address add "$left_address" dev "$left_name"
  in_ns "$right" ip address add "$right_address" dev "$right_name"
  in_ns "$left" ip link set dev "$left_name" up
  in_ns "$right" ip link set dev "$right_name" up
}
link gateway east 198.51.100.2/30 wan to-gateway 198.51.100.1/30
link nat-a wan0 "$nat_a/30" wan to-a 198.51.100.5/30
link nat-b wan0 "$nat_b/30" wan to-b 198.51.100.9/30
link a east 192.168.1.2/24 nat-a lan 192.168.1.1/24
link b east 192.168.2.2/24 nat-b lan 192.168.2.1/24
in_ns gateway ip route add default via 198.51.100.1
in_ns nat-a ip route add default via 198.51.100.5
in_ns nat-b ip route add default via 198.51.100.9
in_ns a ip route add default via 192.168.1.1
in_ns b ip route add default via 192.168.2.1
for node in wan nat-a nat-b; do
  in_ns "$node" sysctl -qw net.ipv4.ip_forward=1
done
# Like home routers, the NATs drop unsolicited packets rather than answer
# them, so the first punch to arrive leaves no state that would change the
# NAT's mapping for the other side's.
for node in nat-a nat-b; do
  in_ns "$node" nft -f - <<'NFT'
table ip nat {
  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    oifname "wan0" masquerade
  }
}
table inet filter {
  chain input {
    type filter hook input priority 0; policy accept;
    iifname "wan0" ct state new drop
  }
}
NFT
done
# Counts UDP between the two NATs' public addresses: direct paths only.
in_ns wan nft -f - <<NFT
table inet watch {
  counter direct {}
  chain forward {
    type filter hook forward priority 0; policy accept;
    ip saddr { $nat_a, $nat_b } ip daddr { $nat_a, $nat_b } udp dport != 0 counter name direct
  }
}
NFT
direct_packets() {
  in_ns wan nft -j list counter inet watch direct |
    python3 -c 'import json, sys; print(next(item["counter"]["packets"] for item in json.load(sys.stdin)["nftables"] if "counter" in item))'
}
block_direct() {
  in_ns wan nft add rule inet watch forward ip saddr "{ $nat_a, $nat_b }" ip daddr "{ $nat_a, $nat_b }" drop
}
unblock_direct() {
  local handle
  handle=$(in_ns wan nft -a list chain inet watch forward | sed -n 's/.* drop # handle \([0-9]*\)$/\1/p')
  in_ns wan nft delete rule inet watch forward handle "$handle"
}

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=Porta peer test CA" \
  -keyout "$work/ca.key" -out "$work/ca.pem" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -subj "/CN=198.51.100.2" \
  -keyout "$work/server.key" -out "$work/server.csr" >/dev/null 2>&1
openssl x509 -req -in "$work/server.csr" -CA "$work/ca.pem" -CAkey "$work/ca.key" \
  -CAcreateserial -days 1 -extfile <(printf 'subjectAltName=IP:198.51.100.2\n') \
  -out "$work/server.crt" >/dev/null 2>&1
openssl rand -hex 24 >"$work/token"

ip netns exec "$(ns gateway)" env \
  PORTA_TOKEN="$(<"$work/token")" PORTA_ADMIN_TOKEN="$admin_token" \
  "$server_binary" --listen ":$port" --admin-listen 127.0.0.1:9090 \
  --tls-cert "$work/server.crt" --tls-key "$work/server.key" \
  --client-registry "$work/clients.json" --lease-state "$work/leases.json" \
  --interface porta0 --egress-interface east --pool 10.66.0.0/24 --dns 192.0.2.53 \
  --route 10.20.0.0/16 --peer-to-peer \
  >>"$work/gateway.log" 2>&1 &
gateway_pid=$!
for _ in $(seq 1 100); do
  in_ns gateway ip link show dev porta0 >/dev/null 2>&1 && break
  sleep 0.1
done
in_ns gateway env PORTA_RUNTIME_DIRECTORY="$work/runtime" \
  "$repository_root/scripts/server-up.sh" porta0 10.66.0.1/24 10.66.0.0/24 east "$port" \
  >>"$work/gateway.log" 2>&1
for _ in $(seq 1 60); do
  in_ns gateway curl -fsS --max-time 5 http://127.0.0.1:9090/readyz >/dev/null 2>&1 && break
  sleep 1
done
in_ns gateway curl -fsS --max-time 5 http://127.0.0.1:9090/readyz >/dev/null
in_ns gateway curl -fsS --max-time 5 -H "Authorization: Bearer $admin_token" \
  http://127.0.0.1:9090/api/gateway | grep -q '"peer_to_peer":true'
echo "gateway is ready"

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

start_client() {
  local node=$1
  install -d "/etc/netns/$(ns "$node")"
  printf 'nameserver 127.0.0.53\n' >"/etc/netns/$(ns "$node")/resolv.conf"
  install -d -m 0700 "$work/$node"
  ip netns exec "$(ns "$node")" env PORTA_TOKEN="$(<"$work/token")" PATH="$work/bin:$PATH" \
    "$client_binary" --server "https://198.51.100.2:$port" --ca "$work/ca.pem" \
    --identity "$work/$node/identity.json" --network-state "$work/$node/network-state.json" \
    --interface porta-ci0 --transport h3 >"$work/client-$node.log" 2>&1 &
  client_pids[$node]=$!
}
wait_connected() {
  local node=$1
  for _ in $(seq 1 60); do
    if grep -q "connected address=" "$work/client-$node.log"; then
      sed -n 's/.*connected address=\([0-9.]*\).*/\1/p' "$work/client-$node.log" | tail -n 1
      return 0
    fi
    kill -0 "${client_pids[$node]}" 2>/dev/null || { echo "client $node exited" >&2; return 1; }
    sleep 1
  done
  echo "client $node did not connect" >&2
  return 1
}
# The client's latest direct-path report.
direct_paths() { grep "direct paths:" "$work/client-$1.log" | tail -n 1 || true; }
# Waits up to $3 seconds for client $1's report to match $2.
wait_direct() {
  local node=$1 pattern=$2 seconds=${3:-30}
  for _ in $(seq 1 "$seconds"); do
    direct_paths "$node" | grep -Eq "$pattern" && return 0
    sleep 1
  done
  echo "client $node: direct paths are '$(direct_paths "$node")', want /$pattern/" >&2
  return 1
}

start_client a
start_client b
lease_a=$(wait_connected a)
lease_b=$(wait_connected b)
echo "clients connected: A=$lease_a, B=$lease_b"

wait_direct a "direct paths: $lease_b via $nat_b:[0-9]+"
wait_direct b "direct paths: $lease_a via $nat_a:[0-9]+"
echo "the clients punched through both NATs"

before=$(direct_packets)
in_ns a ping -n -c 5 -i 0.2 -W 2 "$lease_b" >/dev/null
in_ns b ping -n -c 5 -i 0.2 -W 2 "$lease_a" >/dev/null
after=$(direct_packets)
(( after - before >= 20 )) || { echo "only $((after - before)) packets took the direct path" >&2; exit 1; }
echo "traffic between the clients takes the direct path"

block_direct
# Each side gives up on a silent path on its own clock; until both have,
# replies may still take the broken path.
wait_direct a "direct paths: none" 20
wait_direct b "direct paths: none" 20
in_ns a ping -n -c 3 -i 0.2 -W 2 "$lease_b" >/dev/null
echo "traffic returns to the gateway when the direct path breaks"
unblock_direct
wait_direct a "direct paths: $lease_b via $nat_b:[0-9]+" 60
before=$(direct_packets)
in_ns a ping -n -c 3 -i 0.2 -W 2 "$lease_b" >/dev/null
(( $(direct_packets) - before >= 6 )) || { echo "the healed path does not carry traffic" >&2; exit 1; }
echo "the direct path comes back when the network heals"

kill -INT "${client_pids[b]}"
wait "${client_pids[b]}" 2>/dev/null || true
unset 'client_pids[b]'
wait_direct a "direct paths: none" 20
echo "a device leaving ends its peers' paths to it"
echo "peer-to-peer test passed"
