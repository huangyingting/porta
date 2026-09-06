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

ip link show dev "$tun_interface" >/dev/null
ip link show dev "$external_interface" >/dev/null
ip address replace "$gateway_cidr" dev "$tun_interface"
ip link set dev "$tun_interface" up
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
  if nft list table ip porta >/dev/null 2>&1; then
    echo "delete table ip porta"
  fi
  if nft list table inet porta_guard >/dev/null 2>&1; then
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

if command -v iptables >/dev/null && iptables -w -S DOCKER-USER >/dev/null 2>&1; then
  iptables -w -C DOCKER-USER -i "$tun_interface" -o "$external_interface" -m comment --comment porta -j ACCEPT 2>/dev/null ||
    iptables -w -I DOCKER-USER 1 -i "$tun_interface" -o "$external_interface" -m comment --comment porta -j ACCEPT
  iptables -w -C DOCKER-USER -i "$external_interface" -o "$tun_interface" -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment porta -j ACCEPT 2>/dev/null ||
    iptables -w -I DOCKER-USER 2 -i "$external_interface" -o "$tun_interface" -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment porta -j ACCEPT
fi

echo "configured $tun_interface; Porta nftables forwarding and public-input guards are active"
