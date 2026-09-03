#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: sudo $0 <tun-interface>" >&2
  exit 2
fi

tun_interface=$1
nft delete table ip htun 2>/dev/null || true
ip link set dev "$tun_interface" down 2>/dev/null || true
echo "removed nftables table 'ip htun' and lowered $tun_interface"

