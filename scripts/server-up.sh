#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 4 ]]; then
  echo "usage: sudo $0 <tun-interface> <gateway-cidr> <pool-cidr> <external-interface>" >&2
  echo "example: sudo $0 porta0 10.66.0.1/24 10.66.0.0/24 eth0" >&2
  exit 2
fi

tun_interface=$1
gateway_cidr=$2
pool_cidr=$3
external_interface=$4

ip link show dev "$tun_interface" >/dev/null
ip link show dev "$external_interface" >/dev/null
ip address replace "$gateway_cidr" dev "$tun_interface"
ip link set dev "$tun_interface" up
sysctl -w net.ipv4.ip_forward=1
if [[ -e "/proc/sys/net/ipv6/conf/$tun_interface/disable_ipv6" ]]; then
  sysctl -w "net.ipv6.conf.$tun_interface.disable_ipv6=1"
fi

nft list table ip porta >/dev/null 2>&1 || nft add table ip porta
nft list chain ip porta forward >/dev/null 2>&1 || nft 'add chain ip porta forward { type filter hook forward priority filter; policy accept; }'
nft list chain ip porta postrouting >/dev/null 2>&1 || nft 'add chain ip porta postrouting { type nat hook postrouting priority srcnat; policy accept; }'
nft flush chain ip porta forward
nft flush chain ip porta postrouting
nft add rule ip porta forward iifname "$tun_interface" oifname "$external_interface" accept
nft add rule ip porta forward iifname "$external_interface" oifname "$tun_interface" ct state established,related accept
nft add rule ip porta forward iifname "$tun_interface" drop
nft add rule ip porta forward oifname "$tun_interface" drop
nft add rule ip porta postrouting oifname "$external_interface" ip saddr "$pool_cidr" masquerade

if command -v iptables >/dev/null && iptables -w -S DOCKER-USER >/dev/null 2>&1; then
  iptables -w -C DOCKER-USER -i "$tun_interface" -o "$external_interface" -m comment --comment porta -j ACCEPT 2>/dev/null ||
    iptables -w -I DOCKER-USER 1 -i "$tun_interface" -o "$external_interface" -m comment --comment porta -j ACCEPT
  iptables -w -C DOCKER-USER -i "$external_interface" -o "$tun_interface" -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment porta -j ACCEPT 2>/dev/null ||
    iptables -w -I DOCKER-USER 2 -i "$external_interface" -o "$tun_interface" -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment porta -j ACCEPT
fi

echo "configured $tun_interface; nftables table 'ip porta' contains the forwarding rules"
