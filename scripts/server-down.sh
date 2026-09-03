#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "usage: sudo $0 <tun-interface> [external-interface]" >&2
  exit 2
fi

tun_interface=$1
external_interface=${2:-}
if [[ -n "$external_interface" ]] && command -v iptables >/dev/null && iptables -w -S DOCKER-USER >/dev/null 2>&1; then
  iptables -w -D DOCKER-USER -i "$tun_interface" -o "$external_interface" -m comment --comment htun -j ACCEPT 2>/dev/null || true
  iptables -w -D DOCKER-USER -i "$external_interface" -o "$tun_interface" -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment htun -j ACCEPT 2>/dev/null || true
fi
nft delete table ip htun 2>/dev/null || true
ip link set dev "$tun_interface" down 2>/dev/null || true
echo "removed nftables table 'ip htun' and lowered $tun_interface"
