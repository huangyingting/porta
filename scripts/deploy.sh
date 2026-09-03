#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Deploy or upgrade a direct hTun HTTP/2 + HTTP/3 gateway managed by systemd.

Usage:
  sudo ./scripts/deploy.sh --domain DOMAIN [--cert CERTIFICATE --key PRIVATE_KEY] [options]

Required:
  --domain DOMAIN           TLS hostname used by clients

Options:
  --cert PATH               Certificate managed by an external issuer
  --key PATH                Matching private key; required with --cert
  --acme-email EMAIL        Optional Let's Encrypt account contact
  --port PORT               Direct TCP and UDP port (default: 443)
  --admin-port PORT         Loopback health and metrics port (default: 9090)
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

When --cert and --key are omitted, hTun obtains and renews a Let's Encrypt
certificate using HTTP-01. Public TCP port 80 must reach this server and must
not already be owned by another process.
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
acme_email=
port=443
admin_port=9090
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
    --acme-email) require_value "$@"; acme_email=$2; shift 2 ;;
    --port) require_value "$@"; port=$2; shift 2 ;;
    --admin-port) require_value "$@"; admin_port=$2; shift 2 ;;
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
if [[ -n $certificate || -n $private_key ]]; then
  [[ $certificate == /* && -f $certificate ]] || die "--cert must name an existing absolute path"
  [[ $private_key == /* && -f $private_key ]] || die "--key must name an existing absolute path"
  [[ $certificate != *[$'\n\r\t ']* && $private_key != *[$'\n\r\t ']* ]] ||
    die "certificate paths containing whitespace are not supported"
  [[ $certificate =~ ^/[A-Za-z0-9_./:@+-]+$ && $private_key =~ ^/[A-Za-z0-9_./:@+-]+$ ]] ||
    die "certificate paths contain unsupported characters"
  tls_mode=static
else
  tls_mode=acme
fi
email_pattern='^[A-Za-z0-9._+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'
[[ -z $acme_email || $acme_email =~ $email_pattern ]] ||
  die "invalid --acme-email"
[[ $port =~ ^[0-9]+$ && $port -ge 1 && $port -le 65535 ]] || die "invalid --port"
[[ $admin_port =~ ^[0-9]+$ && $admin_port -ge 1 && $admin_port -le 65535 ]] ||
  die "invalid --admin-port"
(( admin_port != port )) || die "--admin-port must differ from --port"
[[ $mtu =~ ^[0-9]+$ && $mtu -ge 576 && $mtu -le 1400 ]] || die "invalid --mtu"
[[ $tun_interface =~ ^[A-Za-z0-9_.:-]+$ ]] || die "invalid --tun-interface"
[[ $pool =~ ^[0-9.]+/[0-9]+$ ]] || die "invalid --pool"
[[ $dns =~ ^[0-9.]+$ ]] || die "invalid --dns"

for command in install systemctl ip nft openssl curl sed awk make getent sudo sysctl python3 ss grep; do
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

if [[ $tls_mode == static ]]; then
  certificate_public_key=$(openssl x509 -in "$certificate" -pubkey -noout) ||
    die "could not read certificate"
  private_public_key=$(openssl pkey -in "$private_key" -pubout) ||
    die "could not read private key"
  [[ $certificate_public_key == "$private_public_key" ]] ||
    die "certificate and private key do not match"
  openssl x509 -in "$certificate" -checkhost "$domain" -noout >/dev/null ||
    die "certificate does not cover $domain"
else
  (( port != 80 )) || die "--port 80 cannot be used with Let's Encrypt HTTP-01"
  port80_listeners=$(ss -H -ltnp 'sport = :80')
  if [[ -n $port80_listeners ]] &&
    { grep -qv '"htun-server"' <<<"$port80_listeners" ||
      ! systemctl cat htun.service 2>/dev/null | grep -q -- '--acme-domain'; }; then
    die "TCP port 80 is already in use; provide --cert and --key or free port 80 for Let's Encrypt HTTP-01"
  fi
fi

tcp_listeners=$(ss -H -ltnp "sport = :$port")
udp_listeners=$(ss -H -lunp "sport = :$port")
if { [[ -n $tcp_listeners ]] && grep -qv '"htun-server"' <<<"$tcp_listeners"; } ||
  { [[ -n $udp_listeners ]] && grep -qv '"htun-server"' <<<"$udp_listeners"; }; then
  die "TCP or UDP port $port is already used by another service"
fi
admin_listeners=$(ss -H -ltnp "sport = :$admin_port")
if [[ -n $admin_listeners ]] && grep -qv '"htun-server"' <<<"$admin_listeners"; then
  die "TCP admin port $admin_port is already used by another service"
fi

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
install -m 0755 scripts/server-up.sh scripts/server-down.sh scripts/sync-cert.sh \
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

rollback_directory=$(mktemp -d)
deployment_complete=false
had_active_service=false
for unit in htun.service htun-cert-sync.service htun-cert-sync.timer; do
  if [[ -f /etc/systemd/system/$unit ]]; then
    cp -a "/etc/systemd/system/$unit" "$rollback_directory/$unit"
  fi
done
if systemctl is-active --quiet htun.service; then
  had_active_service=true
fi
rollback() {
  local status=$?
  if [[ $status -ne 0 && $deployment_complete == false ]]; then
    set +e
    systemctl stop htun.service
    for unit in htun.service htun-cert-sync.service htun-cert-sync.timer; do
      if [[ -f $rollback_directory/$unit ]]; then
        cp -a "$rollback_directory/$unit" "/etc/systemd/system/$unit"
      else
        rm -f "/etc/systemd/system/$unit"
      fi
    done
    systemctl daemon-reload
    if $had_active_service; then
      systemctl restart htun.service
    fi
    echo "deploy: restored the previous hTun service after deployment failure" >&2
  fi
  rm -f "$rollback_directory/htun.service" \
    "$rollback_directory/htun-cert-sync.service" \
    "$rollback_directory/htun-cert-sync.timer"
  rmdir "$rollback_directory"
  exit "$status"
}
trap rollback EXIT

if systemctl is-active --quiet htun.service; then
  systemctl stop htun.service
fi
if $reset_leases && [[ -s $lease_state ]]; then
  mv "$lease_state" "$lease_state.$(date -u +%Y%m%dT%H%M%SZ).bak"
fi

if [[ $tls_mode == static ]]; then
  unit_after="After=network-online.target htun-cert-sync.service"
  unit_wants="Wants=network-online.target htun-cert-sync.service"
  tls_arguments="--tls-cert /etc/htun/tls/server.crt --tls-key /etc/htun/tls/server.key"
  tls_preflight="ExecStartPre=/bin/sh -c 'test -s /etc/htun/tls/server.crt && test -s /etc/htun/tls/server.key'"
  capabilities=CAP_NET_ADMIN
else
  unit_after="After=network-online.target"
  unit_wants="Wants=network-online.target"
  tls_arguments="--acme-domain $domain --acme-cache /var/lib/htun/acme --acme-http-listen :80"
  if [[ -n $acme_email ]]; then
    tls_arguments+=" --acme-email $acme_email"
  fi
  tls_preflight=
  capabilities="CAP_NET_ADMIN CAP_NET_BIND_SERVICE"
fi
if (( port < 1024 )) && [[ $capabilities != *CAP_NET_BIND_SERVICE* ]]; then
  capabilities+=" CAP_NET_BIND_SERVICE"
fi

cat >/etc/systemd/system/htun.service <<EOF
[Unit]
Description=hTun VPN gateway
$unit_after
$unit_wants

[Service]
Type=simple
EnvironmentFile=/etc/htun/htun.env
$tls_preflight
ExecStart=/usr/local/bin/htun-server --listen :$port --admin-listen 127.0.0.1:$admin_port $tls_arguments --client-token-file /etc/htun/clients --interface $tun_interface --pool $pool --lease-state /var/lib/htun/leases.json --dns $dns --mtu $mtu --json-logs
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
CapabilityBoundingSet=$capabilities
AmbientCapabilities=$capabilities
DevicePolicy=closed
DeviceAllow=/dev/net/tun rw

[Install]
WantedBy=multi-user.target
EOF

if [[ $tls_mode == static ]]; then
  cat >/etc/systemd/system/htun-cert-sync.service <<EOF
[Unit]
Description=Synchronize the hTun TLS certificate

[Service]
Type=oneshot
ExecStart=/usr/local/libexec/htun/sync-cert.sh $certificate $private_key /etc/htun/tls
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
EOF

  install -m 0644 deploy/htun-cert-sync.timer /etc/systemd/system/htun-cert-sync.timer
else
  systemctl disable --now htun-cert-sync.timer >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/htun-cert-sync.service /etc/systemd/system/htun-cert-sync.timer
fi
sysctl -p /etc/sysctl.d/99-htun-quic.conf >/dev/null
systemctl daemon-reload
systemctl enable htun.service >/dev/null
if [[ $tls_mode == static ]]; then
  systemctl enable htun-cert-sync.timer >/dev/null
  systemctl start htun-cert-sync.service
fi
systemctl restart htun.service
if [[ $tls_mode == static ]]; then
  systemctl start htun-cert-sync.timer
fi

for _ in $(seq 1 30); do
  if curl --silent --show-error --fail "http://127.0.0.1:$admin_port/readyz" >/dev/null; then
    break
  fi
  sleep 1
done
curl --silent --show-error --fail "http://127.0.0.1:$admin_port/readyz" >/dev/null ||
  die "gateway started but did not become ready"
cover_page=$(curl --silent --show-error --fail \
  --resolve "$domain:$port:127.0.0.1" "https://$domain:$port/") ||
  die "gateway admin endpoint is ready but public TLS is unavailable"
grep -q '<title>Welcome</title>' <<<"$cover_page" ||
  die "public endpoint did not return the expected landing page"
systemctl is-active --quiet htun.service ||
  die "gateway exited after its readiness check"
ss -H -ltnp "sport = :$port" | grep -q '"htun-server"' ||
  die "gateway is not listening on public TCP port $port"
ss -H -lunp "sport = :$port" | grep -q '"htun-server"' ||
  die "gateway is not listening on public UDP port $port"

deployment_complete=true
cat <<EOF

hTun is ready.

Direct endpoint: https://$domain:$port
Transports:      HTTP/2 over TCP $port and HTTP/3 MASQUE over UDP $port
TLS mode:        $tls_mode
Admin endpoint:  http://127.0.0.1:$admin_port
Android token:   sudo sed -n 's/^HTUN_TOKEN=//p' /etc/htun/htun.env
Ensure both TCP and UDP $port are allowed by the host and cloud firewalls.
EOF
