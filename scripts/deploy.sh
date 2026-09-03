#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Deploy or upgrade a direct hTun HTTP/2 + HTTP/3 gateway managed by systemd.

Usage:
  sudo ./scripts/deploy.sh --domain DOMAIN --cert CERTIFICATE --key PRIVATE_KEY [options]

Required:
  --domain DOMAIN           TLS hostname used by clients
  --cert PATH               Certificate file managed by Caddy or another issuer
  --key PATH                Matching private key file

Options:
  --port PORT               Direct TCP and UDP port (default: 8443)
  --external-interface IF   Internet-facing interface (auto-detected)
  --tun-interface IF        TUN interface (default: htun0)
  --pool CIDR               Client pool (default: 10.66.0.0/24)
  --gateway-cidr CIDR       Gateway address and prefix (default: 10.66.0.1/24)
  --dns ADDRESS             DNS server advertised to clients (default: 1.1.1.1)
  --mtu MTU                 Tunnel MTU (default: 1100)
  --reset-leases            Archive leases incompatible with a changed pool
  --no-build                Install the existing bin/htun-server
  --help                    Show this help

The script preserves existing /etc/htun credentials. On a new installation it
creates random fallback and metrics tokens, but never prints them.
EOF
}

die() {
  echo "deploy: $*" >&2
  exit 1
}

require_value() {
  [[ $# -ge 2 && -n "$2" ]] || die "$1 requires a value"
}

domain=
certificate=
private_key=
port=8443
external_interface=
tun_interface=htun0
pool=10.66.0.0/24
gateway_cidr=
dns=1.1.1.1
mtu=1100
build=true
reset_leases=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --domain) require_value "$@"; domain=$2; shift 2 ;;
    --cert) require_value "$@"; certificate=$2; shift 2 ;;
    --key) require_value "$@"; private_key=$2; shift 2 ;;
    --port) require_value "$@"; port=$2; shift 2 ;;
    --external-interface) require_value "$@"; external_interface=$2; shift 2 ;;
    --tun-interface) require_value "$@"; tun_interface=$2; shift 2 ;;
    --pool) require_value "$@"; pool=$2; shift 2 ;;
    --gateway-cidr) require_value "$@"; gateway_cidr=$2; shift 2 ;;
    --dns) require_value "$@"; dns=$2; shift 2 ;;
    --mtu) require_value "$@"; mtu=$2; shift 2 ;;
    --reset-leases) reset_leases=true; shift ;;
    --no-build) build=false; shift ;;
    --help|-h) usage; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done

[[ $EUID -eq 0 ]] || die "run this script with sudo"
[[ $domain =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ && $domain == *.* ]] ||
  die "--domain must be a DNS hostname"
[[ $certificate == /* && -f $certificate ]] || die "--cert must name an existing absolute path"
[[ $private_key == /* && -f $private_key ]] || die "--key must name an existing absolute path"
[[ $certificate != *[$'\n\r\t ']* && $private_key != *[$'\n\r\t ']* ]] ||
  die "certificate paths containing whitespace are not supported"
[[ $port =~ ^[0-9]+$ && $port -ge 1 && $port -le 65535 ]] || die "invalid --port"
[[ $mtu =~ ^[0-9]+$ && $mtu -ge 576 && $mtu -le 1400 ]] || die "invalid --mtu"
[[ $tun_interface =~ ^[A-Za-z0-9_.:-]+$ ]] || die "invalid --tun-interface"
[[ $pool =~ ^[0-9.]+/[0-9]+$ ]] || die "invalid --pool"
[[ $dns =~ ^[0-9.]+$ ]] || die "invalid --dns"
[[ $certificate =~ ^/[A-Za-z0-9_./:@+-]+$ && $private_key =~ ^/[A-Za-z0-9_./:@+-]+$ ]] ||
  die "certificate paths contain unsupported characters"

for command in install systemctl ip nft openssl curl sed awk make getent sudo sysctl python3; do
  command -v "$command" >/dev/null || die "required command not found: $command"
done

if [[ -z $external_interface ]]; then
  external_interface=$(ip -4 route show default | awk 'NR == 1 { for (i = 1; i <= NF; i++) if ($i == "dev") { print $(i + 1); exit } }')
fi
[[ $external_interface =~ ^[A-Za-z0-9_.:-]+$ ]] || die "could not determine a valid external interface"
ip link show dev "$external_interface" >/dev/null 2>&1 ||
  die "external interface does not exist: $external_interface"

derived_gateway_cidr=$(python3 - "$pool" <<'PY'
import ipaddress
import sys

network = ipaddress.IPv4Network(sys.argv[1], strict=True)
if network.num_addresses < 4:
    raise SystemExit("client pool must contain at least four addresses")
print(f"{network.network_address + 1}/{network.prefixlen}")
PY
) || die "invalid --pool"
python3 - "$dns" <<'PY' || die "invalid --dns"
import ipaddress
import sys

address = ipaddress.ip_address(sys.argv[1])
if not isinstance(address, ipaddress.IPv4Address) or address.is_unspecified:
    raise SystemExit(1)
PY
if [[ -z $gateway_cidr ]]; then
  gateway_cidr=$derived_gateway_cidr
elif [[ $gateway_cidr != "$derived_gateway_cidr" ]]; then
  die "--gateway-cidr must be $derived_gateway_cidr for pool $pool"
fi

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repository_root"

certificate_public_key=$(openssl x509 -in "$certificate" -pubkey -noout) ||
  die "could not read certificate"
private_public_key=$(openssl pkey -in "$private_key" -pubout) ||
  die "could not read private key"
[[ $certificate_public_key == "$private_public_key" ]] ||
  die "certificate and private key do not match"
openssl x509 -in "$certificate" -checkhost "$domain" -noout >/dev/null ||
  die "certificate does not cover $domain"

if $build; then
  go_binary=$(command -v go || true)
  if [[ -z $go_binary ]]; then
    for candidate in /usr/local/go/bin/go /usr/local/bin/go /usr/bin/go; do
      if [[ -x $candidate ]]; then
        go_binary=$candidate
        break
      fi
    done
  fi
  [[ -n $go_binary ]] || die "Go is required to build hTun"
  if [[ -n ${SUDO_USER:-} && $SUDO_USER != root ]]; then
    sudo -u "$SUDO_USER" env "HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)" \
      make GO="$go_binary" build
  else
    make GO="$go_binary" build
  fi
fi
[[ -x bin/htun-server ]] || die "bin/htun-server is missing; remove --no-build or run make build"

lease_state=/var/lib/htun/leases.json
if [[ -s $lease_state ]] && ! python3 - "$pool" "$lease_state" <<'PY'
import ipaddress
import json
import sys

network = ipaddress.IPv4Network(sys.argv[1], strict=True)
gateway = network.network_address + 1
with open(sys.argv[2], encoding="utf-8") as stream:
    state = json.load(stream)
for value in state.get("leases", {}).values():
    address = value if isinstance(value, str) else value.get("address")
    if address is None:
        raise SystemExit(1)
    parsed = ipaddress.IPv4Address(address)
    if not gateway < parsed < network.broadcast_address:
        raise SystemExit(1)
PY
then
  if ! $reset_leases; then
    die "existing leases are outside $pool; rerun with --reset-leases to archive them"
  fi
fi

install -d -m 0755 /usr/local/libexec/htun /etc/htun
install -m 0755 bin/htun-server /usr/local/bin/htun-server
install -m 0755 scripts/server-up.sh scripts/server-down.sh scripts/sync-caddy-cert.sh \
  /usr/local/libexec/htun/
install -m 0644 deploy/99-htun-quic.conf /etc/sysctl.d/99-htun-quic.conf

environment_file=/etc/htun/htun.env
if [[ ! -f $environment_file ]]; then
  umask 077
  {
    printf 'HTUN_TOKEN=%s\n' "$(openssl rand -hex 32)"
    printf 'HTUN_METRICS_TOKEN=%s\n' "$(openssl rand -hex 32)"
  } >"$environment_file"
fi
chmod 0600 "$environment_file"
if [[ ! -f /etc/htun/clients ]]; then
  install -m 0600 /dev/null /etc/htun/clients
else
  chmod 0600 /etc/htun/clients
fi

if systemctl is-active --quiet htun.service; then
  systemctl stop htun.service
fi
if $reset_leases && [[ -s $lease_state ]]; then
  mv "$lease_state" "$lease_state.$(date -u +%Y%m%dT%H%M%SZ).bak"
fi

cat >/etc/systemd/system/htun.service <<EOF
[Unit]
Description=hTun VPN gateway
After=network-online.target htun-cert-sync.service
Wants=network-online.target htun-cert-sync.service

[Service]
Type=simple
EnvironmentFile=/etc/htun/htun.env
ExecStartPre=/bin/sh -c 'test -s /etc/htun/tls/server.crt && test -s /etc/htun/tls/server.key'
ExecStart=/usr/local/bin/htun-server --listen :$port --tls-cert /etc/htun/tls/server.crt --tls-key /etc/htun/tls/server.key --client-token-file /etc/htun/clients --interface $tun_interface --pool $pool --lease-state /var/lib/htun/leases.json --dns $dns --mtu $mtu --json-logs
ExecStartPost=/bin/bash -c 'for i in \$(seq 1 50); do /usr/sbin/ip link show dev $tun_interface >/dev/null 2>&1 && exec /usr/local/libexec/htun/server-up.sh $tun_interface $gateway_cidr $pool $external_interface; sleep 0.1; done; exit 1'
ExecStopPost=/usr/local/libexec/htun/server-down.sh $tun_interface $external_interface
Restart=on-failure
RestartSec=2
TimeoutStopSec=15
LimitNOFILE=65536
UMask=0077
StateDirectory=htun
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ProtectControlGroups=true
ProtectKernelLogs=true
ProtectKernelModules=true
ProtectClock=true
ProtectHostname=true
RestrictSUIDSGID=true
LockPersonality=true
RestrictRealtime=true
SystemCallArchitectures=native
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
CapabilityBoundingSet=CAP_NET_ADMIN
AmbientCapabilities=CAP_NET_ADMIN
DevicePolicy=closed
DeviceAllow=/dev/net/tun rw

[Install]
WantedBy=multi-user.target
EOF

cat >/etc/systemd/system/htun-cert-sync.service <<EOF
[Unit]
Description=Synchronize the hTun TLS certificate

[Service]
Type=oneshot
ExecStart=/usr/local/libexec/htun/sync-caddy-cert.sh $certificate $private_key /etc/htun/tls
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
EOF

install -m 0644 deploy/htun-cert-sync.timer /etc/systemd/system/htun-cert-sync.timer
cat >/etc/htun/Caddyfile.example <<EOF
$domain {
  @metrics path /metrics
  respond @metrics 404

  reverse_proxy https://127.0.0.1:$port {
    flush_interval -1
    transport http {
      tls_server_name $domain
    }
  }
}
EOF

sysctl -p /etc/sysctl.d/99-htun-quic.conf >/dev/null
systemctl daemon-reload
systemctl enable htun.service htun-cert-sync.timer >/dev/null
systemctl start htun-cert-sync.service
systemctl restart htun.service
systemctl start htun-cert-sync.timer

for _ in $(seq 1 30); do
  if curl --silent --show-error --fail \
    --resolve "$domain:$port:127.0.0.1" "https://$domain:$port/readyz" >/dev/null; then
    break
  fi
  sleep 1
done
curl --silent --show-error --fail \
  --resolve "$domain:$port:127.0.0.1" "https://$domain:$port/readyz" >/dev/null ||
  die "gateway started but did not become ready"

cat <<EOF

hTun is ready.

Direct endpoint: https://$domain:$port
Transports:      HTTP/2 over TCP $port and HTTP/3 MASQUE over UDP $port
Android token:   sudo sed -n 's/^HTUN_TOKEN=//p' /etc/htun/htun.env
Caddy example:   /etc/htun/Caddyfile.example

Ensure both TCP and UDP $port are allowed by the host and cloud firewalls.
EOF
