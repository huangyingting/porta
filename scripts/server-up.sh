#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 5 || $# -gt 6 ]]; then
  echo "usage: sudo $0 <tun-interface> <gateway-cidr> <pool-cidr> <external-interface> <public-port> [--auto-mtu=BOOL]" >&2
  echo "example: sudo $0 porta0 10.66.0.1/24 10.66.0.0/24 eth0 8443" >&2
  exit 2
fi

tun_interface=$1
gateway_cidr=$2
pool_cidr=$3
external_interface=$4
public_port=$5
auto_mtu=true
case "${6:---auto-mtu=true}" in
  --auto-mtu|--auto-mtu=true) ;;
  --auto-mtu=false) auto_mtu=false ;;
  *) echo "invalid MTU mode; use --auto-mtu=true or --auto-mtu=false" >&2; exit 2 ;;
esac

[[ $tun_interface =~ ^[A-Za-z0-9_.:-]{1,15}$ &&
   $external_interface =~ ^[A-Za-z0-9_.:-]{1,15}$ &&
   $tun_interface != "$external_interface" &&
   $gateway_cidr =~ ^[0-9.]+/[0-9]+$ &&
   $pool_cidr =~ ^[0-9.]+/[0-9]+$ &&
   $public_port =~ ^[0-9]{1,5}$ ]] || {
  echo "invalid interface, IPv4 CIDR, or public port" >&2
  exit 2
}
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
if $auto_mtu; then
  # Gateway-sourced ICMP enters through TUN; allow it without weakening
  # source validation on physical interfaces.
  sysctl -w "net/ipv4/conf/$tun_interface/accept_local=1"
  sysctl -w "net/ipv4/conf/$tun_interface/rp_filter=2"
fi
if [[ -e "/proc/sys/net/ipv6/conf/$tun_interface/disable_ipv6" ]]; then
  sysctl -w "net/ipv6/conf/$tun_interface/disable_ipv6=1"
fi

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
    iifname "$tun_interface" oifname "$external_interface" accept
    iifname "$external_interface" oifname "$tun_interface" ct state established,related accept
    iifname "$tun_interface" drop
    oifname "$tun_interface" drop
  }
  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    oifname "$external_interface" ip saddr $pool_cidr masquerade
  }
}
table inet porta_guard {
  chain input {
    type filter hook input priority -10; policy accept;
    iifname "$external_interface" meta nfproto ipv4 tcp dport $public_port ct state new tcp flags & (fin | syn | rst | ack) == syn meter tcp4 size 65535 { ip saddr timeout 10s limit rate over 200/second burst 400 packets } counter drop
    iifname "$external_interface" meta nfproto ipv6 tcp dport $public_port ct state new tcp flags & (fin | syn | rst | ack) == syn meter tcp6 size 65535 { ip6 saddr timeout 10s limit rate over 200/second burst 400 packets } counter drop
    iifname "$external_interface" meta nfproto ipv4 udp dport $public_port ct state new meter udp4 size 65535 { ip saddr timeout 10s limit rate over 500/second burst 1000 packets } counter drop
    iifname "$external_interface" meta nfproto ipv6 udp dport $public_port ct state new meter udp6 size 65535 { ip6 saddr timeout 10s limit rate over 500/second burst 1000 packets } counter drop
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
      printf '%s\n' "$external_interface"
    } | awk 'NF && !seen[$0]++' >"$docker_rules_state"
    for tracked_external_interface in "${tracked_external_interfaces[@]}"; do
      [[ $tracked_external_interface == "$external_interface" ]] && continue
      remove_docker_rule -i "$tun_interface" -o "$tracked_external_interface" -m comment --comment porta -j ACCEPT ||
        { echo "could not remove previous Porta Docker rule" >&2; exit 1; }
      remove_docker_rule -i "$tracked_external_interface" -o "$tun_interface" -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment porta -j ACCEPT ||
        { echo "could not remove previous Porta Docker rule" >&2; exit 1; }
    done
    ensure_docker_rule 1 -i "$tun_interface" -o "$external_interface" -m comment --comment porta -j ACCEPT ||
      { echo "could not install Porta Docker rule" >&2; exit 1; }
    ensure_docker_rule 2 -i "$external_interface" -o "$tun_interface" -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment porta -j ACCEPT ||
      { echo "could not install Porta Docker rule" >&2; exit 1; }
    printf '%s\n' "$external_interface" >"$docker_rules_state"
  fi
else
  rm -f "$docker_rules_state"
fi

echo "configured $tun_interface; Porta nftables forwarding and public-input guards are active"
