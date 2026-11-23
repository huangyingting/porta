#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: sudo $0 <tun-interface> <gateway-cidr> <pool-cidr> <external-interface> <public-port> [--upstream-interface IF] [--exit-interface IF]... [--local-exit] [--client-host-access]" >&2
  echo "example: sudo $0 porta0 10.66.0.1/24 10.66.0.0/24 eth0 8443" >&2
  echo "cascade relay: sudo $0 porta0 10.66.0.1/24 10.66.0.0/24 eth0 8443 --upstream-interface porta-up0" >&2
  exit 2
}
[[ $# -ge 5 ]] || usage

tun_interface=$1
gateway_cidr=$2
pool_cidr=$3
external_interface=$4
public_port=$5
shift 5
upstream_interface=
exit_interfaces=()
local_exit=false
client_host_access=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    --upstream-interface)
      [[ $# -ge 2 && -z $upstream_interface ]] || usage
      upstream_interface=$2
      shift 2
      ;;
    --exit-interface)
      [[ $# -ge 2 && ${#exit_interfaces[@]} -lt 8 ]] || usage
      exit_interfaces+=("$2")
      shift 2
      ;;
    --local-exit) local_exit=true; shift ;;
    --client-host-access) client_host_access=true; shift ;;
    *) usage ;;
  esac
done
for exit_interface in "${exit_interfaces[@]}"; do
  [[ $exit_interface =~ ^[A-Za-z0-9_.:-]{1,15}$ &&
     $exit_interface != "$tun_interface" &&
     $exit_interface != "$external_interface" &&
     $exit_interface != "$upstream_interface" ]] || {
    echo "invalid or reused exit interface" >&2
    exit 2
  }
done
if [[ -n $(printf '%s\n' "${exit_interfaces[@]}" | sort | uniq -d) ]]; then
  echo "exit interfaces must be distinct" >&2
  exit 2
fi
if $local_exit && [[ -z $upstream_interface ]]; then
  echo "--local-exit only applies with --upstream-interface" >&2
  exit 2
fi
[[ $tun_interface =~ ^[A-Za-z0-9_.:-]{1,15}$ &&
   $external_interface =~ ^[A-Za-z0-9_.:-]{1,15}$ &&
   $tun_interface != "$external_interface" &&
   ( -z $upstream_interface ||
     ( $upstream_interface =~ ^[A-Za-z0-9_.:-]{1,15}$ &&
       $upstream_interface != "$tun_interface" &&
       $upstream_interface != "$external_interface" ) ) &&
   $gateway_cidr =~ ^[0-9.]+/[0-9]+$ &&
   $pool_cidr =~ ^[0-9.]+/[0-9]+$ &&
   $public_port =~ ^[0-9]{1,5}$ ]] || {
  echo "invalid interface, IPv4 CIDR, or public port" >&2
  exit 2
}
# Client traffic leaves through the physical interface, or through the
# next-hop gateway's tunnel when this gateway is a cascade relay.
forward_interface=${upstream_interface:-$external_interface}
# Cascade policy routing; server-down.sh removes the same entries. Named
# exit i uses table 10067+i; the daemon routes selected leases to it.
relay_table=10066
relay_priority=10066
first_exit_table=10067
max_exits=8
# Every interface client traffic may leave through: the default egress, the
# named exits, and on a relay with --local-exit the physical interface.
egress_interfaces=("$forward_interface" "${exit_interfaces[@]}")
if $local_exit; then
  egress_interfaces+=("$external_interface")
fi
relay_interfaces=("${exit_interfaces[@]}")
if [[ -n $upstream_interface ]]; then
  relay_interfaces=("$upstream_interface" "${exit_interfaces[@]}")
fi
public_port=$((10#$public_port))
(( public_port >= 1 && public_port <= 65535 )) || {
  echo "invalid public port" >&2
  exit 2
}

state_directory=${PORTA_RUNTIME_DIRECTORY:-/run/porta}
[[ $state_directory == /* && $state_directory != *[$'\n\r\t ']* ]] || {
  echo "invalid Porta runtime directory" >&2
  exit 2
}
umask 077
mkdir -p "$state_directory"
[[ -d $state_directory && ! -L $state_directory ]] || {
  echo "Porta runtime path is not a directory" >&2
  exit 1
}
chmod 0700 "$state_directory"
ip_forward_state="$state_directory/ip-forward-$tun_interface"
docker_rules_state="$state_directory/docker-rules-$tun_interface"

remove_docker_rule() {
  while true; do
    if iptables -w -C DOCKER-USER "$@" 2>/dev/null; then
      iptables -w -D DOCKER-USER "$@" || return
      continue
    else
      check_status=$?
    fi
    [[ $check_status -eq 1 ]] && return 0
    return "$check_status"
  done
}

ensure_docker_rule() {
  position=$1
  shift
  if iptables -w -C DOCKER-USER "$@" 2>/dev/null; then
    return 0
  else
    check_status=$?
  fi
  [[ $check_status -eq 1 ]] || return "$check_status"
  iptables -w -I DOCKER-USER "$position" "$@"
}

nft_tables=$(nft list tables) || {
  echo "could not inspect existing nftables tables" >&2
  exit 1
}
ip link show dev "$tun_interface" >/dev/null
ip link show dev "$external_interface" >/dev/null
for relay_interface in "${relay_interfaces[@]}"; do
  ip link show dev "$relay_interface" >/dev/null
done
ip address replace "$gateway_cidr" dev "$tun_interface"
ip link set dev "$tun_interface" up
if [[ -e $ip_forward_state ]]; then
  original_ip_forward=$(<"$ip_forward_state")
else
  original_ip_forward=$(sysctl -n net.ipv4.ip_forward)
  [[ $original_ip_forward == 0 || $original_ip_forward == 1 ]] || {
    echo "could not read the original IPv4 forwarding state" >&2
    exit 1
  }
  printf '%s\n' "$original_ip_forward" >"$ip_forward_state"
fi
[[ $original_ip_forward == 0 || $original_ip_forward == 1 ]] || {
  echo "invalid saved IPv4 forwarding state" >&2
  exit 1
}
sysctl -w net.ipv4.ip_forward=1
# Live datagram limits can shrink even with a fixed interface MTU.
# Permit gateway ICMP only on the owned TUN, not physical interfaces.
sysctl -w "net/ipv4/conf/$tun_interface/accept_local=1"
sysctl -w "net/ipv4/conf/$tun_interface/rp_filter=2"
if [[ -e "/proc/sys/net/ipv6/conf/$tun_interface/disable_ipv6" ]]; then
  sysctl -w "net/ipv6/conf/$tun_interface/disable_ipv6=1"
fi
for relay_interface in "${relay_interfaces[@]}"; do
  # Relayed replies arrive on the upstream tunnel although the main table
  # routes their Internet sources through the physical interface. The next
  # hop's gateway may share this gateway's address when pools overlap, so its
  # MTU feedback must not be discarded as a martian.
  sysctl -w "net/ipv4/conf/$relay_interface/rp_filter=2"
  sysctl -w "net/ipv4/conf/$relay_interface/accept_local=1"
  if [[ -e "/proc/sys/net/ipv6/conf/$relay_interface/disable_ipv6" ]]; then
    sysctl -w "net/ipv6/conf/$relay_interface/disable_ipv6=1"
  fi
done

{
  if grep -Fxq 'table ip porta' <<<"$nft_tables"; then
    echo "delete table ip porta"
  fi
  if grep -Fxq 'table inet porta_guard' <<<"$nft_tables"; then
    echo "delete table inet porta_guard"
  fi
  cat <<EOF
table ip porta {
  chain forward {
    type filter hook forward priority filter; policy accept;
EOF
  # The default egress rules stay first; readiness checks their order.
  for egress_interface in "${egress_interfaces[@]}"; do
    printf '    iifname "%s" oifname "%s" accept\n' "$tun_interface" "$egress_interface"
    printf '    iifname "%s" oifname "%s" ct state established,related accept\n' "$egress_interface" "$tun_interface"
  done
  cat <<EOF
    # Traffic between clients never reaches the kernel: the daemon switches
    # it between sessions under each account's access policy.
    iifname "$tun_interface" drop
    oifname "$tun_interface" drop
  }
  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
EOF
  for egress_interface in "${egress_interfaces[@]}"; do
    printf '    oifname "%s" ip saddr %s masquerade\n' "$egress_interface" "$pool_cidr"
  done
  echo "  }"
  if [[ ${#relay_interfaces[@]} -gt 0 ]]; then
    echo "  chain relay_mss {"
    echo "    type filter hook forward priority mangle; policy accept;"
    for relay_interface in "${relay_interfaces[@]}"; do
      printf '    iifname "%s" oifname "%s" tcp flags & (syn | rst) == syn tcp option maxseg size set rt mtu\n' "$tun_interface" "$relay_interface"
      printf '    iifname "%s" oifname "%s" tcp flags & (syn | rst) == syn tcp option maxseg size set rt mtu\n' "$relay_interface" "$tun_interface"
    done
    echo "  }"
    echo "  chain relay_input {"
    echo "    type filter hook input priority filter; policy accept;"
    for relay_interface in "${relay_interfaces[@]}"; do
      printf '    iifname "%s" ct state established,related accept\n' "$relay_interface"
      printf '    iifname "%s" drop\n' "$relay_interface"
    done
    echo "  }"
  fi
  # Clients never reach link-local services such as cloud instance metadata,
  # which would otherwise disclose the gateway VM's credentials. The forward
  # proxy applies the same rule to CONNECT destinations.
  cat <<EOF
  chain client_forward_guard {
    type filter hook forward priority -10; policy accept;
    iifname "$tun_interface" ip daddr { 169.254.0.0/16, 100.100.100.200 } drop
  }
EOF
  if ! $client_host_access; then
    # Clients may ping the gateway and use a resolver on it; other host
    # services stay unreachable from the tunnel.
    cat <<EOF
  chain client_input {
    type filter hook input priority filter; policy accept;
    iifname "$tun_interface" ct state established,related accept
    iifname "$tun_interface" icmp type { echo-request, destination-unreachable, time-exceeded, parameter-problem } accept
    iifname "$tun_interface" meta l4proto { tcp, udp } th dport 53 accept
    iifname "$tun_interface" drop
  }
EOF
  fi
  cat <<EOF
}
table inet porta_guard {
  # Per-source rate tracking uses explicit dynamic sets, the form current
  # nftables lists for the deprecated meter syntax as well.
  set tcp4 { type ipv4_addr; size 65535; flags dynamic,timeout; }
  set tcp6 { type ipv6_addr; size 65535; flags dynamic,timeout; }
  set udp4 { type ipv4_addr; size 65535; flags dynamic,timeout; }
  set udp6 { type ipv6_addr; size 65535; flags dynamic,timeout; }
  chain input {
    type filter hook input priority -10; policy accept;
    iifname "$external_interface" meta nfproto ipv4 tcp dport $public_port ct state new tcp flags & (fin | syn | rst | ack) == syn update @tcp4 { ip saddr timeout 10s limit rate over 200/second burst 400 packets } counter drop
    iifname "$external_interface" meta nfproto ipv6 tcp dport $public_port ct state new tcp flags & (fin | syn | rst | ack) == syn update @tcp6 { ip6 saddr timeout 10s limit rate over 200/second burst 400 packets } counter drop
    iifname "$external_interface" meta nfproto ipv4 udp dport $public_port ct state new update @udp4 { ip saddr timeout 10s limit rate over 500/second burst 1000 packets } counter drop
    iifname "$external_interface" meta nfproto ipv6 udp dport $public_port ct state new update @udp6 { ip6 saddr timeout 10s limit rate over 500/second burst 1000 packets } counter drop
  }
}
EOF
} | nft -f -

tracked_external_interfaces=()
if [[ -e $docker_rules_state ]]; then
  mapfile -t tracked_external_interfaces <"$docker_rules_state"
fi
for tracked_external_interface in "${tracked_external_interfaces[@]}"; do
  [[ $tracked_external_interface =~ ^[A-Za-z0-9_.:-]{1,15}$ ]] || {
    echo "saved Docker rule interface is invalid" >&2
    exit 1
  }
done
if [[ ${#tracked_external_interfaces[@]} -gt 0 ]] && ! command -v iptables >/dev/null; then
  echo "iptables is required to reconcile previously installed Docker rules" >&2
  exit 1
fi
if command -v iptables >/dev/null; then
  docker_rules=$(iptables -w -S) || {
    echo "could not inspect existing Docker rules" >&2
    exit 1
  }
  if ! grep -Fxq -- '-N DOCKER-USER' <<<"$docker_rules"; then
    rm -f "$docker_rules_state"
  else
    {
      printf '%s\n' "${tracked_external_interfaces[@]}"
      printf '%s\n' "${egress_interfaces[@]}"
    } | awk 'NF && !seen[$0]++' >"$docker_rules_state"
    for tracked_external_interface in "${tracked_external_interfaces[@]}"; do
      [[ " ${egress_interfaces[*]} " == *" $tracked_external_interface "* ]] && continue
      remove_docker_rule -i "$tun_interface" -o "$tracked_external_interface" -m comment --comment porta -j ACCEPT ||
        { echo "could not remove previous Porta Docker rule" >&2; exit 1; }
      remove_docker_rule -i "$tracked_external_interface" -o "$tun_interface" -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment porta -j ACCEPT ||
        { echo "could not remove previous Porta Docker rule" >&2; exit 1; }
    done
    position=1
    for egress_interface in "${egress_interfaces[@]}"; do
      ensure_docker_rule "$position" -i "$tun_interface" -o "$egress_interface" -m comment --comment porta -j ACCEPT ||
        { echo "could not install Porta Docker rule" >&2; exit 1; }
      ensure_docker_rule "$((position + 1))" -i "$egress_interface" -o "$tun_interface" -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment porta -j ACCEPT ||
        { echo "could not install Porta Docker rule" >&2; exit 1; }
      position=$((position + 2))
    done
    printf '%s\n' "${egress_interfaces[@]}" >"$docker_rules_state"
  fi
else
  rm -f "$docker_rules_state"
fi

relay_rule_present() {
  local rules line
  rules=$(ip -4 rule show) || return 2
  while IFS= read -r line; do
    [[ $line == "$relay_priority:"*" iif $tun_interface lookup $relay_table"* ]] && return 0
  done <<<"$rules"
  return 1
}
for _ in 1 2 3 4 5 6 7 8; do
  if relay_rule_present; then
    ip -4 rule del priority "$relay_priority" iif "$tun_interface" lookup "$relay_table"
  else
    rule_status=$?
    [[ $rule_status -eq 1 ]] || { echo "could not inspect policy routing rules" >&2; exit 1; }
    break
  fi
done
ip -4 route flush table "$relay_table" 2>/dev/null || true
for ((index = 0; index < max_exits; index++)); do
  ip -4 route flush table "$((first_exit_table + index))" 2>/dev/null || true
done
for index in "${!exit_interfaces[@]}"; do
  # Leases the daemon routes to this exit never fall back to another path.
  exit_table=$((first_exit_table + index))
  ip link set dev "${exit_interfaces[$index]}" up
  ip -4 route replace default dev "${exit_interfaces[$index]}" table "$exit_table"
  ip -4 route replace unreachable default metric 4294967295 table "$exit_table"
done
if [[ -n $upstream_interface ]]; then
  # Send client traffic to the next hop. The unreachable fallback keeps it
  # from reaching the main table's physical default route while the upstream
  # interface is missing; client-to-client traffic stays on the main table,
  # where the forward chain drops it.
  ip link set dev "$upstream_interface" up
  ip -4 route replace default dev "$upstream_interface" table "$relay_table"
  ip -4 route replace unreachable default metric 4294967295 table "$relay_table"
  ip -4 route replace throw "$pool_cidr" table "$relay_table"
  ip -4 rule add priority "$relay_priority" iif "$tun_interface" lookup "$relay_table"
  echo "configured $tun_interface; client traffic is relayed through $upstream_interface"
  if $local_exit; then
    echo "accounts may select the local exit through $external_interface"
  fi
else
  echo "configured $tun_interface; Porta nftables forwarding and public-input guards are active"
fi
