#!/usr/bin/env bash
# Turns this host into a transport relay for a Porta gateway: it forwards
# TCP and UDP on one port, unchanged, to the gateway. Clients keep the
# gateway's URL and dial the relay with --relay-address (or a profile's
# Relay address). Traffic stays encrypted end to end: the relay never holds
# tokens, TLS keys or tunnel traffic, and the gateway is still the exit.
#
# Usage:
#   sudo scripts/relay.sh up GATEWAY_IP:PORT [--port PORT] [--allow CIDR[,CIDR...]] [--persist]
#   sudo scripts/relay.sh down
#   sudo scripts/relay.sh status
#
# --port     the port clients dial on this host (default: the gateway's port)
# --allow    accept only these client networks (default: any)
# --persist  restore the relay at boot with a porta-relay systemd service
set -euo pipefail

table=porta_relay
rules=/etc/porta-relay.nft
unit=/etc/systemd/system/porta-relay.service
sysctl_file=/etc/sysctl.d/90-porta-relay.conf

die() { echo "relay.sh: $*" >&2; exit 2; }
usage() { sed -n '9,16p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2; }

[[ $# -ge 1 ]] || usage
action=$1
shift
[[ $EUID -eq 0 ]] || die "run with sudo"
command -v nft >/dev/null || die "nft (nftables) is required"

case $action in
  down)
    nft delete table inet "$table" 2>/dev/null || true
    if [[ -f $unit ]]; then
      systemctl disable --now porta-relay.service >/dev/null 2>&1 || true
      rm -f "$unit" "$rules" "$sysctl_file"
      systemctl daemon-reload
    fi
    echo "relay removed"
    exit 0
    ;;
  status)
    nft list table inet "$table" 2>/dev/null || { echo "no relay is configured"; exit 1; }
    exit 0
    ;;
  up) ;;
  *) usage ;;
esac

[[ $# -ge 1 ]] || usage
target=$1
shift
listen_port=
allow=
persist=false
while [[ $# -gt 0 ]]; do
  case $1 in
    --port) [[ $# -ge 2 ]] || usage; listen_port=$2; shift 2 ;;
    --port=*) listen_port=${1#*=}; shift ;;
    --allow) [[ $# -ge 2 ]] || usage; allow=$2; shift 2 ;;
    --allow=*) allow=${1#*=}; shift ;;
    --persist) persist=true; shift ;;
    *) usage ;;
  esac
done

valid_port() { [[ $1 =~ ^[1-9][0-9]{0,4}$ ]] && (($1 <= 65535)); }
if [[ $target =~ ^([0-9]{1,3}(\.[0-9]{1,3}){3}):([0-9]+)$ ]]; then
  family=ip
  gateway=${BASH_REMATCH[1]}
  gateway_port=${BASH_REMATCH[3]}
  IFS=. read -r a b c d <<<"$gateway"
  for octet in "$a" "$b" "$c" "$d"; do
    ((10#$octet <= 255)) || die "invalid gateway address $gateway"
  done
  destination="$gateway:$gateway_port"
elif [[ $target =~ ^\[([0-9A-Fa-f:.]+)\]:([0-9]+)$ ]]; then
  family=ip6
  gateway=${BASH_REMATCH[1]}
  gateway_port=${BASH_REMATCH[2]}
  destination="[$gateway]:$gateway_port"
else
  die "the gateway must be IP:PORT or [IPv6]:PORT, such as 203.0.113.10:8443"
fi
valid_port "$gateway_port" || die "invalid gateway port $gateway_port"
listen_port=${listen_port:-$gateway_port}
valid_port "$listen_port" || die "invalid --port $listen_port"

source_match=
if [[ -n $allow ]]; then
  for network in ${allow//,/ }; do
    if [[ $family == ip ]]; then
      [[ $network =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}(/[0-9]{1,2})?$ ]] || die "invalid --allow network $network"
    else
      [[ $network =~ ^[0-9A-Fa-f:.]+(/[0-9]{1,3})?$ ]] || die "invalid --allow network $network"
    fi
  done
  source_match="$family saddr { ${allow//,/, } } "
fi

# Clients dial this host; the gateway sees the relay as their address, so
# replies come back through it. New flows are rate limited to blunt floods.
ruleset=$(cat <<EOF
table inet $table {
  chain prerouting {
    type nat hook prerouting priority dstnat; policy accept;
    meta nfproto $([[ $family == ip ]] && echo ipv4 || echo ipv6) meta l4proto { tcp, udp } th dport $listen_port ${source_match}dnat $family to $destination
  }
  chain forward {
    type filter hook forward priority filter - 1; policy accept;
    ct status dnat $family daddr $gateway meta l4proto { tcp, udp } th dport $gateway_port ct state new limit rate over 200/second burst 400 packets drop
  }
  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    ct status dnat $family daddr $gateway meta l4proto { tcp, udp } th dport $gateway_port masquerade
  }
}
EOF
)

nft delete table inet "$table" 2>/dev/null || true
nft -f - <<<"$ruleset"
if [[ $family == ip ]]; then
  forwarding=net.ipv4.ip_forward
else
  forwarding=net.ipv6.conf.all.forwarding
fi
sysctl -qw "$forwarding=1"

if [[ $persist == true ]]; then
  command -v systemctl >/dev/null || die "--persist needs systemd"
  printf '%s\n' "$ruleset" >"$rules"
  printf '%s = 1\n' "$forwarding" >"$sysctl_file"
  cat >"$unit" <<EOF
[Unit]
Description=Porta transport relay to $destination
After=network-pre.target
Wants=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/sysctl -qw $forwarding=1
ExecStart=/usr/sbin/nft -f $rules
ExecStop=/usr/sbin/nft delete table inet $table

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable porta-relay.service >/dev/null
fi

echo "relaying TCP and UDP port $listen_port to $destination${allow:+ for $allow}"
echo "clients: keep the gateway URL and set the relay address to <this host's IP>:$listen_port"
