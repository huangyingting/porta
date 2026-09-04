#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "usage: sudo $0 <tun-interface> [external-interface]" >&2
  exit 2
fi

tun_interface=$1
external_interface=${2:-}
status=0
[[ $tun_interface =~ ^[A-Za-z0-9_.:-]{1,15}$ &&
   ( -z $external_interface || $external_interface =~ ^[A-Za-z0-9_.:-]{1,15}$ ) ]] || {
  echo "invalid interface" >&2
  exit 2
}
if [[ -n "$external_interface" ]] && command -v iptables >/dev/null && iptables -w -S DOCKER-USER >/dev/null 2>&1; then
  while iptables -w -C DOCKER-USER -i "$tun_interface" -o "$external_interface" -m comment --comment porta -j ACCEPT 2>/dev/null; do
    if ! iptables -w -D DOCKER-USER -i "$tun_interface" -o "$external_interface" -m comment --comment porta -j ACCEPT; then
      status=1
      break
    fi
  done
  while iptables -w -C DOCKER-USER -i "$external_interface" -o "$tun_interface" -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment porta -j ACCEPT 2>/dev/null; do
    if ! iptables -w -D DOCKER-USER -i "$external_interface" -o "$tun_interface" -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment porta -j ACCEPT; then
      status=1
      break
    fi
  done
fi
if nft list table ip porta >/dev/null 2>&1; then
  nft delete table ip porta || status=1
fi
if ip link show dev "$tun_interface" >/dev/null 2>&1; then
  ip link set dev "$tun_interface" down || status=1
fi
if [[ $status -eq 0 ]]; then
  echo "removed nftables table 'ip porta' and lowered $tun_interface"
else
  echo "could not completely remove Porta networking for $tun_interface" >&2
fi
exit "$status"
