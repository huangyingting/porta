#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Deploy or upgrade a direct Porta HTTP/2 + HTTP/3 gateway managed by systemd.

Usage:
  sudo ./scripts/deploy.sh --domain DOMAIN [--cert CERTIFICATE --key PRIVATE_KEY] [options]

Required:
  --domain DOMAIN           TLS hostname used by clients

Options:
  --cert PATH               Certificate managed by an external issuer
  --key PATH                Matching private key; required with --cert
  --acme-email EMAIL        Optional Let's Encrypt account contact
  --port PORT               Direct TCP and UDP port (default: 443)
  --admin-port PORT         Loopback admin UI and operations port (default: 9090)
  --external-interface IF   Internet-facing interface (auto-detected)
  --tun-interface IF        TUN interface (default: porta0)
  --pool CIDR               Client pool (default: 10.66.0.0/24)
  --gateway-cidr CIDR       Gateway address and prefix (default: 10.66.0.1/24)
  --dns ADDRESS             DNS server advertised to clients (default: 1.1.1.1)
  --mtu MTU                 Tunnel MTU ceiling (default: 1400)
  --auto-mtu[=BOOL]         Automatic HTTP/3 MTU selection (default: true)
  --trust-proxy-headers     Trust client IP headers from a loopback reverse proxy
  --disable-forward-proxy   Disable authenticated HTTPS CONNECT proxying
  --reset-leases            Archive leases incompatible with a changed pool
  --release VERSION         GitHub release to deploy (default: latest)
  --build-local             Build the server from the current checkout instead
  --help                    Show this help

The script preserves existing /etc/porta credentials. On a new installation it
creates random client, admin, and metrics tokens.

When --cert and --key are omitted, Porta obtains and renews a Let's Encrypt
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
tun_interface=porta0
pool=10.66.0.0/24
gateway_cidr=
dns=1.1.1.1
mtu=1400
auto_mtu=true
trust_proxy_headers=false
forward_proxy=true
release=latest
build_local=false
reset_leases=false
client_version=

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
    --auto-mtu|--auto-mtu=true) auto_mtu=true; shift ;;
    --auto-mtu=false) auto_mtu=false; shift ;;
    --trust-proxy-headers) trust_proxy_headers=true; shift ;;
    --disable-forward-proxy) forward_proxy=false; shift ;;
    --reset-leases) reset_leases=true; shift ;;
    --release) require_value "$@"; release=$2; shift 2 ;;
    --build-local) build_local=true; shift ;;
    --help|-h) usage; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done

[[ $EUID -eq 0 ]] || die "run this script with sudo"
[[ ${#domain} -le 253 &&
   ! $domain =~ ^[0-9.]+$ &&
   $domain =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$ ]] ||
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
[[ $port =~ ^[0-9]{1,5}$ ]] || die "invalid --port"
[[ $admin_port =~ ^[0-9]{1,5}$ ]] || die "invalid --admin-port"
port=$((10#$port))
admin_port=$((10#$admin_port))
(( port >= 1 && port <= 65535 )) || die "invalid --port"
(( admin_port >= 1 && admin_port <= 65535 )) || die "invalid --admin-port"
(( admin_port != port )) || die "--admin-port must differ from --port"
[[ $mtu =~ ^[0-9]{1,4}$ ]] || die "invalid --mtu"
mtu=$((10#$mtu))
(( mtu >= 576 && mtu <= 1400 )) || die "invalid --mtu"
[[ $tun_interface =~ ^[A-Za-z0-9_.:-]{1,15}$ ]] || die "invalid --tun-interface"
[[ $pool =~ ^[0-9.]+/[0-9]+$ ]] || die "invalid --pool"
[[ $dns =~ ^[0-9.]+$ ]] || die "invalid --dns"
[[ $release == latest || $release =~ ^v[0-9][A-Za-z0-9._-]*$ ]] ||
  die "--release must be latest or a tag beginning with v"

for command in install systemctl ip nft openssl curl sed awk sysctl python3 ss grep sha256sum uname flock; do
  command -v "$command" >/dev/null || die "required command not found: $command"
done
if $build_local; then
  for command in make getent; do
    command -v "$command" >/dev/null || die "required command not found: $command"
  done
  if [[ -n ${SUDO_USER:-} && $SUDO_USER != root ]]; then
    command -v sudo >/dev/null || die "required command not found: sudo"
  fi
fi
if [[ $tls_mode == static ]]; then
  resolved_certificate=$(python3 -c 'import os, sys; print(os.path.realpath(sys.argv[1]))' "$certificate")
  resolved_private_key=$(python3 -c 'import os, sys; print(os.path.realpath(sys.argv[1]))' "$private_key")
  [[ $resolved_certificate != *[$'\n\r\t ']* && $resolved_private_key != *[$'\n\r\t ']* &&
     $resolved_certificate =~ ^/[A-Za-z0-9_./:@+-]+$ && $resolved_private_key =~ ^/[A-Za-z0-9_./:@+-]+$ ]] ||
    die "resolved certificate paths contain unsupported characters"
  # Keep the issuer's live symlink paths so renewal can replace their targets.
  for path in "$certificate" "$private_key" "$resolved_certificate" "$resolved_private_key"; do
    case "$path" in
      /tmp/*|/var/tmp/*) die "certificate paths must not reside or resolve inside a temporary directory" ;;
    esac
  done
fi

if [[ -z $external_interface ]]; then
  external_interface=$(ip -4 route show default | awk 'NR == 1 { for (i = 1; i <= NF; i++) if ($i == "dev") { print $(i + 1); exit } }')
fi
[[ $external_interface =~ ^[A-Za-z0-9_.:-]{1,15}$ ]] || die "could not determine a valid external interface"
[[ $external_interface != "$tun_interface" ]] || die "TUN and external interfaces must differ"
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

exec 9>/run/lock/porta-deploy.lock
flock -n 9 || die "another deployment is already running"

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
  (( port != 80 && admin_port != 80 )) ||
    die "public and admin ports must differ from Let's Encrypt HTTP-01 port 80"
  port80_listeners=$(ss -H -ltnp 'sport = :80')
  if [[ -n $port80_listeners ]] &&
    { grep -qv '"porta-server"' <<<"$port80_listeners" ||
      ! systemctl cat porta.service 2>/dev/null | grep -q -- '--acme-domain'; }; then
    die "TCP port 80 is already in use; provide --cert and --key or free port 80 for Let's Encrypt HTTP-01"
  fi
fi

tcp_listeners=$(ss -H -ltnp "sport = :$port")
udp_listeners=$(ss -H -lunp "sport = :$port")
if { [[ -n $tcp_listeners ]] && grep -qv '"porta-server"' <<<"$tcp_listeners"; } ||
  { [[ -n $udp_listeners ]] && grep -qv '"porta-server"' <<<"$udp_listeners"; }; then
  die "TCP or UDP port $port is already used by another service"
fi
admin_listeners=$(ss -H -ltnp "sport = :$admin_port")
if [[ -n $admin_listeners ]] && grep -qv '"porta-server"' <<<"$admin_listeners"; then
  die "TCP admin port $admin_port is already used by another service"
fi

server_binary=
release_download_directory=
client_release_assets=(
  porta-client-linux-amd64
  porta-client-linux-arm64
  porta-client-windows-amd64.zip
  porta-android-arm64-v8a.apk
  porta-android-armeabi-v7a.apk
  porta-android-x86_64.apk
)
if $build_local; then
  go_binary=$(command -v go || true)
  if [[ -z $go_binary ]]; then
    for candidate in /usr/local/go/bin/go /usr/local/bin/go /usr/bin/go; do
      if [[ -x $candidate ]]; then
        go_binary=$candidate
        break
      fi
    done
  fi
  [[ -n $go_binary ]] || die "Go is required to build Porta"
  if [[ -n ${SUDO_USER:-} && $SUDO_USER != root ]]; then
    sudo -u "$SUDO_USER" env "HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)" \
      make GO="$go_binary" build
  else
    make GO="$go_binary" build
  fi
  server_binary=bin/porta-server
else
  case "$(uname -m)" in
    x86_64|amd64) release_arch=amd64 ;;
    aarch64|arm64) release_arch=arm64 ;;
    *) die "GitHub releases do not provide a server binary for $(uname -m)" ;;
  esac
  release_asset=porta-server-linux-$release_arch
  release_artifacts=("$release_asset" SHA256SUMS "${client_release_assets[@]}")
  release_download_directory=$(mktemp -d)
  cleanup_release_download() {
    local artifact
    for artifact in "${release_artifacts[@]}" release.json github-auth-header; do
      rm -f "$release_download_directory/$artifact"
    done
    rmdir "$release_download_directory"
  }
  trap cleanup_release_download EXIT

  github_api_headers=(
    --header "Accept: application/vnd.github+json"
    --header "X-GitHub-Api-Version: 2022-11-28"
  )
  github_token=${GH_TOKEN:-${GITHUB_TOKEN:-}}
  if [[ -n $github_token ]]; then
    [[ $github_token != *[$'\r\n']* ]] || die "GitHub token contains invalid characters"
    github_auth_header="$release_download_directory/github-auth-header"
    printf 'Authorization: Bearer %s\n' "$github_token" >"$github_auth_header"
    chmod 0600 "$github_auth_header"
    github_api_headers+=(--header "@$github_auth_header")
  fi
  if [[ $release == latest ]]; then
    release_api_url=https://api.github.com/repos/huangyingting/porta/releases/latest
  else
    release_api_url=https://api.github.com/repos/huangyingting/porta/releases/tags/$release
  fi
  curl --fail --location --silent --show-error "${github_api_headers[@]}" \
    "$release_api_url" \
    --output "$release_download_directory/release.json" ||
    die "could not read GitHub release metadata; private repositories require GH_TOKEN"
  client_version=$(python3 - "$release_download_directory/release.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as release_file:
    value = json.load(release_file).get("tag_name", "")
if not isinstance(value, str) or not value or len(value) > 128 or any(c.isspace() for c in value):
    raise SystemExit("release metadata has an invalid tag name")
print(value)
PY
  ) || die "release metadata does not contain a valid version"
  mapfile -t release_asset_urls < <(python3 - \
    "$release_download_directory/release.json" "${release_artifacts[@]}" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as release_file:
    release = json.load(release_file)
assets = {asset["name"]: asset["url"] for asset in release.get("assets", [])}
for name in sys.argv[2:]:
    url = assets.get(name)
    if not url:
        raise SystemExit(f"release asset not found: {name}")
    print(url)
PY
  ) || die "release metadata is missing required assets"
  [[ ${#release_asset_urls[@]} -eq ${#release_artifacts[@]} ]] ||
    die "release metadata is missing required assets"
  github_api_headers[1]="Accept: application/octet-stream"
  for index in "${!release_artifacts[@]}"; do
    curl --fail --location --silent --show-error "${github_api_headers[@]}" \
      "${release_asset_urls[$index]}" \
      --output "$release_download_directory/${release_artifacts[$index]}"
  done
  for artifact in "$release_asset" "${client_release_assets[@]}"; do
    expected_checksum=$(awk -v asset="$artifact" '$2 == asset { print $1; exit }' \
      "$release_download_directory/SHA256SUMS")
    [[ $expected_checksum =~ ^[0-9a-f]{64}$ ]] ||
      die "release checksum does not contain $artifact"
    actual_checksum=$(sha256sum "$release_download_directory/$artifact" | awk '{ print $1 }')
    [[ $actual_checksum == "$expected_checksum" ]] ||
      die "checksum verification failed for $artifact"
  done
  server_binary="$release_download_directory/$release_asset"
fi
[[ -f $server_binary ]] || die "Porta server binary is missing"
chmod 0755 "$server_binary"
server_help=$("$server_binary" --help 2>&1)
grep -q -- 'client-downloads' <<<"$server_help" ||
  die "selected server release does not support the required client download portal"
grep -q -- 'landing-template-dir' <<<"$server_help" ||
  die "selected server release does not support custom landing templates"
if $trust_proxy_headers && ! grep -q -- 'trust-proxy-headers' <<<"$server_help"; then
  die "selected server release does not support trusted reverse-proxy client addresses"
fi

lease_state=/var/lib/porta/leases.json
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

downloads_stage=
deployment_complete=false
had_active_service=false
had_active_timer=false
services_paused=false
deployment_started=false
leases_archive=
service_enabled=$(systemctl is-enabled porta.service 2>/dev/null || true)
timer_enabled=$(systemctl is-enabled porta-cert-sync.timer 2>/dev/null || true)
[[ $service_enabled != masked* && $timer_enabled != masked* ]] ||
  die "unmask Porta services before deploying"
if systemctl is-active --quiet porta.service; then
  had_active_service=true
fi
if systemctl is-active --quiet porta-cert-sync.timer; then
  had_active_timer=true
fi
sysctl_keys=(net.core.rmem_max net.core.wmem_max net.ipv4.ip_forward)
sysctl_values=()
for key in "${sysctl_keys[@]}"; do
  sysctl_values+=("$(sysctl -n "$key")")
done
backup_file() {
  local source=$1
  local name=$2
  if [[ -f $source ]]; then
    cp -a "$source" "$rollback_directory/$name"
  fi
}
backup_directory() {
  local source=$1
  local name=$2
  if [[ -d $source ]]; then
    cp -a "$source" "$rollback_directory/$name"
  fi
}
restore_file() {
  local name=$1
  local destination=$2
  if [[ -f $rollback_directory/$name ]]; then
    cp -a "$rollback_directory/$name" "$destination"
  else
    rm -f "$destination"
  fi
}
restore_directory() {
  local name=$1
  local destination=$2
  rm -rf "$destination" || return
  if [[ -d $rollback_directory/$name ]]; then
    cp -a "$rollback_directory/$name" "$destination"
  fi
}
restore_enablement() {
  local unit=$1
  local state=$2
  case "$state" in
    enabled) systemctl enable "$unit" >/dev/null ;;
    enabled-runtime) systemctl enable --runtime "$unit" >/dev/null ;;
  esac
}
rollback_run() {
  if ! "$@"; then
    echo "deploy: rollback step failed: $*" >&2
    rollback_failed=true
  fi
}
rollback() {
  local status=$?
  local rollback_failed=false
  set +e
  if [[ $status -ne 0 && $deployment_complete == false ]]; then
    if $deployment_started; then
      rollback_run systemctl stop porta.service
      systemctl stop porta-cert-sync.timer porta-cert-sync.service >/dev/null 2>&1
      systemctl disable porta.service porta-cert-sync.timer >/dev/null 2>&1
      rollback_run restore_file porta-server /usr/local/bin/porta-server
      rollback_run restore_file server-up.sh /usr/local/libexec/porta/server-up.sh
      rollback_run restore_file server-down.sh /usr/local/libexec/porta/server-down.sh
      rollback_run restore_file sync-cert.sh /usr/local/libexec/porta/sync-cert.sh
      rollback_run restore_file 99-porta-quic.conf /etc/sysctl.d/99-porta-quic.conf
      rollback_run restore_directory configuration /etc/porta
      rollback_run restore_directory downloads /var/lib/porta/downloads
      for state in leases clients usage; do
        rollback_run restore_file "$state.json" "/var/lib/porta/$state.json"
      done
      if [[ -n $leases_archive ]]; then
        rollback_run rm -f "$leases_archive"
      fi
      for unit in porta.service porta-cert-sync.service porta-cert-sync.timer; do
        rollback_run restore_file "$unit" "/etc/systemd/system/$unit"
      done
      rollback_run systemctl daemon-reload
      rollback_run restore_enablement porta.service "$service_enabled"
      rollback_run restore_enablement porta-cert-sync.timer "$timer_enabled"
      for index in "${!sysctl_keys[@]}"; do
        rollback_run sysctl -w "${sysctl_keys[$index]}=${sysctl_values[$index]}"
      done
    fi
    if $services_paused; then
      if $had_active_service; then
        rollback_run systemctl restart porta.service
      fi
      if $had_active_timer; then
        rollback_run systemctl start porta-cert-sync.timer
      fi
    fi
    if $rollback_failed; then
      echo "deploy: rollback incomplete; recovery files retained in $rollback_directory" >&2
    else
      echo "deploy: restored the previous Porta installation after deployment failure" >&2
    fi
  fi
  if [[ -n $release_download_directory ]]; then
    cleanup_release_download
  fi
  if [[ -n $downloads_stage ]]; then
    rm -rf "$downloads_stage"
  fi
  if ! $rollback_failed; then
    rm -rf "$rollback_directory"
  fi
  exit "$status"
}
rollback_directory=$(mktemp -d)
trap rollback EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

services_paused=true
# Quiesce writers and run the old unit's cleanup with its original helpers.
systemctl stop porta-cert-sync.timer porta-cert-sync.service >/dev/null 2>&1 || {
  if $had_active_timer || systemctl is-active --quiet porta-cert-sync.service; then
    die "could not stop certificate synchronization"
  fi
}
if $had_active_service; then
  systemctl stop porta.service
fi
backup_file /usr/local/bin/porta-server porta-server
backup_file /usr/local/libexec/porta/server-up.sh server-up.sh
backup_file /usr/local/libexec/porta/server-down.sh server-down.sh
backup_file /usr/local/libexec/porta/sync-cert.sh sync-cert.sh
backup_file /etc/sysctl.d/99-porta-quic.conf 99-porta-quic.conf
backup_directory /etc/porta configuration
backup_directory /var/lib/porta/downloads downloads
for state in leases clients usage; do
  backup_file "/var/lib/porta/$state.json" "$state.json"
done
for unit in porta.service porta-cert-sync.service porta-cert-sync.timer; do
  backup_file "/etc/systemd/system/$unit" "$unit"
done
deployment_started=true
install -d -m 0755 /usr/local/libexec/porta /etc/porta /etc/porta/landing /var/lib/porta/downloads
install -m 0755 "$server_binary" /usr/local/bin/porta-server
install -m 0755 scripts/server-up.sh scripts/server-down.sh scripts/sync-cert.sh \
  /usr/local/libexec/porta/
install -m 0644 deploy/99-porta-quic.conf /etc/sysctl.d/99-porta-quic.conf
if ! $build_local; then
  downloads_stage=$(mktemp -d /var/lib/porta/downloads.new.XXXXXX)
  chmod 0755 "$downloads_stage"
  for artifact in "${client_release_assets[@]}" SHA256SUMS; do
    install -m 0644 "$release_download_directory/$artifact" \
      "$downloads_stage/$artifact"
  done
  printf '%s\n' "$client_version" >"$downloads_stage/CLIENT_VERSION"
  chmod 0644 "$downloads_stage/CLIENT_VERSION"
  cleanup_release_download
  release_download_directory=
fi

environment_file=/etc/porta/porta.env
if [[ ! -f $environment_file ]]; then
  umask 077
  {
    printf 'PORTA_TOKEN=%s\n' "$(openssl rand -hex 32)"
    printf 'PORTA_ADMIN_TOKEN=%s\n' "$(openssl rand -hex 32)"
    printf 'PORTA_METRICS_TOKEN=%s\n' "$(openssl rand -hex 32)"
  } >"$environment_file"
fi
if ! grep -q '^PORTA_TOKEN=' "$environment_file"; then
  printf 'PORTA_TOKEN=%s\n' "$(openssl rand -hex 32)" >>"$environment_file"
fi
if ! grep -q '^PORTA_ADMIN_TOKEN=' "$environment_file"; then
  printf 'PORTA_ADMIN_TOKEN=%s\n' "$(openssl rand -hex 32)" >>"$environment_file"
fi
chmod 0600 "$environment_file"

if [[ -n $downloads_stage ]]; then
  rm -rf /var/lib/porta/downloads
  mv "$downloads_stage" /var/lib/porta/downloads
  downloads_stage=
fi
if $reset_leases && [[ -s $lease_state ]]; then
  leases_archive=$(mktemp "$lease_state.$(date -u +%Y%m%dT%H%M%SZ).XXXXXX.bak")
  mv "$lease_state" "$leases_archive"
fi

if [[ $tls_mode == static ]]; then
  unit_after="After=network-online.target porta-cert-sync.service docker.service"
  unit_wants="Wants=network-online.target porta-cert-sync.service"
  tls_arguments="--tls-cert /etc/porta/tls/server.crt --tls-key /etc/porta/tls/server.key"
  tls_preflight="ExecStartPre=/bin/sh -c 'test -s /etc/porta/tls/server.crt && test -s /etc/porta/tls/server.key'"
  capabilities=CAP_NET_ADMIN
else
  unit_after="After=network-online.target docker.service"
  unit_wants="Wants=network-online.target"
  tls_arguments="--acme-domain $domain --acme-cache /var/lib/porta/acme --acme-http-listen :80"
  if [[ -n $acme_email ]]; then
    tls_arguments+=" --acme-email $acme_email"
  fi
  tls_preflight=
  capabilities="CAP_NET_ADMIN CAP_NET_BIND_SERVICE"
fi
if (( port < 1024 || admin_port < 1024 )) && [[ $capabilities != *CAP_NET_BIND_SERVICE* ]]; then
  capabilities+=" CAP_NET_BIND_SERVICE"
fi
forward_proxy_argument=
if ! $forward_proxy; then
  forward_proxy_argument="--disable-forward-proxy"
fi
trust_proxy_argument=
if $trust_proxy_headers; then
  trust_proxy_argument="--trust-proxy-headers"
fi
auto_mtu_argument="--auto-mtu=$auto_mtu"

if systemctl cat docker.service >/dev/null 2>&1; then
  unit_wants+=" docker.service"
fi

cat >/etc/systemd/system/porta.service <<EOF
[Unit]
Description=Porta VPN gateway
$unit_after
$unit_wants

[Service]
Type=simple
EnvironmentFile=/etc/porta/porta.env
$tls_preflight
ExecStart=/usr/local/bin/porta-server --listen :$port --admin-listen 127.0.0.1:$admin_port $tls_arguments $forward_proxy_argument $trust_proxy_argument $auto_mtu_argument --landing-template-dir /etc/porta/landing --client-downloads /var/lib/porta/downloads --client-registry /var/lib/porta/clients.json --interface $tun_interface --egress-interface $external_interface --pool $pool --lease-state /var/lib/porta/leases.json --dns $dns --mtu $mtu --json-logs
ExecStartPost=/bin/bash -c 'for i in \$(seq 1 50); do /usr/sbin/ip link show dev $tun_interface >/dev/null 2>&1 && exec /usr/local/libexec/porta/server-up.sh $tun_interface $gateway_cidr $pool $external_interface $port $auto_mtu_argument; sleep 0.1; done; exit 1'
ExecStopPost=/usr/local/libexec/porta/server-down.sh $tun_interface $external_interface
Restart=on-failure
RestartSec=2
TimeoutStopSec=15
LimitNOFILE=65536
UMask=0077
StateDirectory=porta
RuntimeDirectory=porta
RuntimeDirectoryMode=0700
RuntimeDirectoryPreserve=yes
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
  cat >/etc/systemd/system/porta-cert-sync.service <<EOF
[Unit]
Description=Synchronize the Porta TLS certificate

[Service]
Type=oneshot
ExecStart=/usr/local/libexec/porta/sync-cert.sh $certificate $private_key /etc/porta/tls
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
EOF

  install -m 0644 deploy/porta-cert-sync.timer /etc/systemd/system/porta-cert-sync.timer
else
  systemctl disable --now porta-cert-sync.timer >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/porta-cert-sync.service /etc/systemd/system/porta-cert-sync.timer
fi
sysctl -p /etc/sysctl.d/99-porta-quic.conf >/dev/null
systemctl daemon-reload
systemctl enable porta.service >/dev/null
if [[ $tls_mode == static ]]; then
  systemctl enable porta-cert-sync.timer >/dev/null
  systemctl start porta-cert-sync.service
fi
systemctl restart porta.service
if [[ $tls_mode == static ]]; then
  systemctl start porta-cert-sync.timer
fi

for _ in $(seq 1 30); do
  if curl --silent --show-error --fail --noproxy '*' --connect-timeout 5 --max-time 10 "http://127.0.0.1:$admin_port/readyz" >/dev/null; then
    break
  fi
  sleep 1
done
curl --silent --show-error --fail --noproxy '*' --connect-timeout 5 --max-time 10 "http://127.0.0.1:$admin_port/readyz" >/dev/null ||
  die "gateway started but did not become ready"
landing_tls_arguments=()
if [[ $tls_mode == static ]]; then
  landing_tls_arguments+=(--cacert /etc/porta/tls/server.crt)
fi
landing_probe=$(curl --silent --show-error --fail --noproxy '*' --head --output /dev/null \
  --write-out '%{http_code}|%{content_type}' --connect-timeout 5 --max-time 30 \
  "${landing_tls_arguments[@]}" \
  --resolve "$domain:$port:127.0.0.1" "https://$domain:$port/") ||
  die "gateway admin endpoint is ready but public TLS is unavailable"
landing_status=${landing_probe%%|*}
landing_content_type=${landing_probe#*|}
[[ $landing_status == 200 ]] ||
  die "public endpoint returned HTTP $landing_status instead of the landing page"
[[ $landing_content_type == text/html* ]] ||
  die "public endpoint did not return an HTML landing page"
systemctl is-active --quiet porta.service ||
  die "gateway exited after its readiness check"
ss -H -ltnp "sport = :$port" | grep -q '"porta-server"' ||
  die "gateway is not listening on public TCP port $port"
ss -H -lunp "sport = :$port" | grep -q '"porta-server"' ||
  die "gateway is not listening on public UDP port $port"
deployment_complete=true

if [[ -f /var/lib/porta/downloads/porta-android-arm64-v8a.apk ]]; then
  public_origin=https://$domain
  if (( port != 443 )); then
    public_origin+=:$port
  fi
  client_download_summary="Client downloads after portal sign-in:
  Linux AMD64: $public_origin/download/porta-client-linux-amd64
  Linux ARM64: $public_origin/download/porta-client-linux-arm64
  Windows:     $public_origin/download/porta-client-windows-amd64.zip
  Android:     $public_origin/download/porta-android-arm64-v8a.apk
  Checksums:   $public_origin/download/SHA256SUMS"
else
  client_download_summary="Client downloads: unavailable until a release deployment publishes artifacts"
fi

cat <<EOF
Porta is ready.

Direct endpoint: https://$domain:$port
Transports:      HTTP/2 over TCP $port and HTTP/3 MASQUE over UDP $port
Forward proxy:   $([[ $forward_proxy == true ]] && echo "enabled (HTTPS CONNECT on port 443 only)" || echo "disabled")
TLS mode:        $tls_mode
Server source:   $([[ $build_local == true ]] && echo "local checkout" || echo "GitHub release $release")
Admin endpoint:  http://127.0.0.1:$admin_port
Browser portal:  https://$domain:$port
Admin token:     sudo sed -n 's/^PORTA_ADMIN_TOKEN=//p' /etc/porta/porta.env
Initial client:  sudo sed -n 's/^PORTA_TOKEN=//p' /etc/porta/porta.env
$client_download_summary
Ensure both TCP and UDP $port are allowed by the host and cloud firewalls.
EOF
