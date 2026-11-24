#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Deploy or upgrade a direct Porta HTTP/2 + HTTP/3 gateway managed by systemd.

Usage:
  sudo ./scripts/deploy.sh --domain DOMAIN [--cert CERTIFICATE --key PRIVATE_KEY] [options]
  sudo ./scripts/deploy.sh [options]     # upgrade, reusing the saved options

Required on the first deployment:
  --domain DOMAIN           TLS hostname used by clients

Options:
  --cert PATH               Certificate managed by an external issuer
  --key PATH                Matching private key; required with --cert
  --acme                    Forget a saved --cert/--key and use Let's Encrypt
  --acme-email EMAIL        Optional Let's Encrypt account contact
  --port PORT               Direct TCP and UDP port (default: 443)
  --admin-port PORT         Loopback admin UI and operations port (default: 9090)
  --external-interface IF   Internet-facing interface (auto-detected)
  --tun-interface IF        TUN interface (default: porta0)
  --pool CIDR               Client pool (default: 10.66.0.0/24)
  --gateway-cidr CIDR       Gateway address and prefix (default: 10.66.0.1/24)
  --dns ADDRESS             DNS server advertised to clients (default: 1.1.1.1)
  --dns-resolver[=BOOL]     Serve DNS on the gateway address instead, with
                            device names under porta.internal
  --dns-upstreams IP[,IP]   Resolvers the built-in resolver forwards to
                            (default: the host's resolvers)
  --dns-forwards D=IP[,...] Send a domain's queries to another resolver, such
                            as an internal zone (DOMAIN=IP or DOMAIN=IP:PORT)
  --dns-blocklist FILE      Domains the built-in resolver refuses; installed as
                            /etc/porta/dns-blocklist.txt. --dns-blocklist= removes it
  --mtu MTU                 Tunnel MTU ceiling (default: 1400)
  --auto-mtu[=BOOL]         Automatic HTTP/3 MTU selection (default: true)
  --trust-proxy-headers[=BOOL]
                            Trust client IP headers from a loopback reverse proxy
  --forward-proxy=BOOL      Authenticated HTTPS CONNECT proxying (default: true);
                            --disable-forward-proxy is the same as =false
  --reset-leases            Archive leases incompatible with a changed pool
  --upstream URL            Relay client traffic through another Porta gateway
                            (cascade relay) instead of exiting from this host
  --upstream-token-file F   File holding the next hop's client token; defaults
                            to $PORTA_UPSTREAM_TOKEN, the saved token, or a prompt
  --upstream-ca PATH        PEM CA for a next hop with a private certificate
  --upstream-interface IF   Upstream TUN interface (default: porta-up0)
  --no-upstream             Stop relaying and exit traffic from this host again
  --exits NAME=URL[,...]    Named next-hop gateways that access policies can
                            select as an account's exit; each token comes from
                            $PORTA_EXIT_TOKEN_<NAME> or the saved one. --exits=
                            removes them
  --local-exit[=BOOL]       With --upstream, also offer this host's egress as
                            the "local" exit
  --client-to-client[=BOOL] Let connected clients reach each other's addresses
  --peer-to-peer[=BOOL]     Let devices that may reach each other connect
                            directly over UDP (HTTP/3 split-tunnel clients)
  --client-host-access[=BOOL]
                            Let clients reach all services on this host; by
                            default they may only ping it and use DNS port 53
  --routes CIDR[,CIDR...]   Split tunnel: clients route only these prefixes
                            through Porta (IPv6 ones need IPv6); --routes=
                            restores a full tunnel
  --ipv6                    Give clients IPv6 too, from a random unique local
                            /64 masqueraded through the external interface
  --ipv6-pool CIDR          Use this IPv6 prefix instead, such as one routed to
                            this host; --no-ipv6 turns IPv6 off again
  --ipv6-routed[=BOOL]      The IPv6 prefix is routed to this host: forward it
                            without NAT
  --dns-domains D[,D...]    Split DNS: clients resolve only these domains with
                            --dns; requires --routes
  --oidc-issuer URL         OpenID Connect issuer for administrator single
                            sign-on; --oidc-issuer= turns it off
  --oidc-client-id ID       Client ID registered with the issuer; the secret, if
                            any, comes from $PORTA_OIDC_CLIENT_SECRET or the
                            saved one. Register https://DOMAIN[:PORT]/auth/oidc/callback
  --federation-primary URL  Mirror accounts from this primary gateway, so one
                            profile can fail over between them; --federation-primary=
                            makes this gateway manage its own accounts again
  --disable-federation      Stop serving accounts to replicas and forget
                            $PORTA_FEDERATION_TOKEN
                            (Set $PORTA_FEDERATION_TOKEN, at least 32 characters, on the
                            primary and every replica; it is saved.)
  --release VERSION         GitHub release to deploy (default: latest)
  --build-local             Build the server from the current checkout instead
  --help                    Show this help

The script preserves existing /etc/porta credentials. On a new installation it
creates random client, admin, and metrics tokens.

Options are saved in /etc/porta/deploy.conf. Later runs start from the saved
options, so an upgrade needs no options; any option given overrides its saved
value and is saved in turn.

When --cert and --key are omitted, Porta obtains and renews a Let's Encrypt
certificate using HTTP-01. Public TCP port 80 must reach this server and must
not already be owned by another process.

Cascade relays chain gateways like multi-hop WireGuard: deploy the exit
gateway normally, create a client token for the relay on it, then deploy the
relay with --upstream https://EXIT-DOMAIN[:PORT]. Repeat for longer chains.
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
upstream=
upstream_token_file=
upstream_ca=
upstream_interface=porta-up0
client_to_client=false
peer_to_peer=false
client_host_access=false
routes=
dns_domains=
exits=
local_exit=false
dns_resolver=false
oidc_issuer=
oidc_client_id=
federation_primary=
disable_federation=false
dns_upstreams=
dns_forwards=
dns_blocklist=
ipv6_pool=
ipv6_routed=false
generate_ipv6=false

# Options persisted across upgrades. Values are parsed, never sourced, and
# validated below exactly like command-line input.
deploy_config=/etc/porta/deploy.conf
saved_option_names=(
  domain certificate private_key acme_email port admin_port external_interface
  tun_interface pool dns mtu auto_mtu trust_proxy_headers forward_proxy upstream
  upstream_ca upstream_interface client_to_client peer_to_peer client_host_access routes
  dns_domains exits local_exit dns_resolver dns_upstreams dns_forwards dns_blocklist oidc_issuer
  oidc_client_id federation_primary ipv6_pool ipv6_routed
)
declare -A saved_options=()
if [[ -e $deploy_config || -L $deploy_config ]]; then
  [[ -f $deploy_config && ! -L $deploy_config ]] ||
    die "$deploy_config must be a regular file"
  line_number=0
  while IFS= read -r line || [[ -n $line ]]; do
    line_number=$((line_number + 1))
    [[ -z $line || $line == \#* ]] && continue
    [[ $line =~ ^([a-z][a-z0-9_]*)=([A-Za-z0-9_./:@+,=-]*)$ ]] ||
      die "invalid line $line_number in $deploy_config"
    key=${BASH_REMATCH[1]}
    value=${BASH_REMATCH[2]}
    [[ " ${saved_option_names[*]} " == *" $key "* ]] ||
      die "unknown option '$key' on line $line_number of $deploy_config"
    saved_options[$key]=$value
    printf -v "$key" '%s' "$value"
  done <"$deploy_config"
fi

parse_bool() {
  case "$2" in
    true|false) printf '%s' "$2" ;;
    *) die "$1 must be true or false" ;;
  esac
}

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
    --acme) certificate=; private_key=; shift ;;
    --trust-proxy-headers) trust_proxy_headers=true; shift ;;
    --trust-proxy-headers=*) trust_proxy_headers=$(parse_bool --trust-proxy-headers "${1#*=}"); shift ;;
    --disable-forward-proxy) forward_proxy=false; shift ;;
    --forward-proxy=*) forward_proxy=$(parse_bool --forward-proxy "${1#*=}"); shift ;;
    --reset-leases) reset_leases=true; shift ;;
    --upstream) require_value "$@"; upstream=$2; shift 2 ;;
    --upstream-token-file) require_value "$@"; upstream_token_file=$2; shift 2 ;;
    --upstream-ca) require_value "$@"; upstream_ca=$2; shift 2 ;;
    --upstream-interface) require_value "$@"; upstream_interface=$2; shift 2 ;;
    --no-upstream) upstream=; upstream_ca=; shift ;;
    --client-to-client) client_to_client=true; shift ;;
    --client-to-client=*) client_to_client=$(parse_bool --client-to-client "${1#*=}"); shift ;;
    --peer-to-peer) peer_to_peer=true; shift ;;
    --peer-to-peer=*) peer_to_peer=$(parse_bool --peer-to-peer "${1#*=}"); shift ;;
    --client-host-access) client_host_access=true; shift ;;
    --client-host-access=*) client_host_access=$(parse_bool --client-host-access "${1#*=}"); shift ;;
    --federation-primary) require_value "$@"; federation_primary=$2; shift 2 ;;
    --federation-primary=*) federation_primary=${1#*=}; shift ;;
    --disable-federation) disable_federation=true; shift ;;
    --oidc-issuer) require_value "$@"; oidc_issuer=$2; shift 2 ;;
    --oidc-issuer=*) oidc_issuer=${1#*=}; shift ;;
    --oidc-client-id) require_value "$@"; oidc_client_id=$2; shift 2 ;;
    --oidc-client-id=*) oidc_client_id=${1#*=}; shift ;;
    --dns-resolver) dns_resolver=true; shift ;;
    --dns-resolver=*) dns_resolver=$(parse_bool --dns-resolver "${1#*=}"); shift ;;
    --dns-upstreams) require_value "$@"; dns_upstreams=$2; shift 2 ;;
    --dns-upstreams=*) dns_upstreams=${1#*=}; shift ;;
    --dns-forwards) require_value "$@"; dns_forwards=$2; shift 2 ;;
    --dns-forwards=*) dns_forwards=${1#*=}; shift ;;
    --dns-blocklist) require_value "$@"; dns_blocklist=$2; shift 2 ;;
    --dns-blocklist=*) dns_blocklist=${1#*=}; shift ;;
    --exits) require_value "$@"; exits=$2; shift 2 ;;
    --exits=*) exits=${1#*=}; shift ;;
    --local-exit) local_exit=true; shift ;;
    --local-exit=*) local_exit=$(parse_bool --local-exit "${1#*=}"); shift ;;
    --ipv6) generate_ipv6=true; shift ;;
    --ipv6-pool) require_value "$@"; ipv6_pool=$2; shift 2 ;;
    --no-ipv6) ipv6_pool=; ipv6_routed=false; generate_ipv6=false; shift ;;
    --ipv6-routed) ipv6_routed=true; shift ;;
    --ipv6-routed=*) ipv6_routed=$(parse_bool --ipv6-routed "${1#*=}"); shift ;;
    --routes) require_value "$@"; routes=$2; shift 2 ;;
    --routes=*) routes=${1#*=}; shift ;;
    --dns-domains) require_value "$@"; dns_domains=$2; shift 2 ;;
    --dns-domains=*) dns_domains=${1#*=}; shift ;;
    --release) require_value "$@"; release=$2; shift 2 ;;
    --build-local) build_local=true; shift ;;
    --help|-h) usage; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done

[[ $EUID -eq 0 ]] || die "run this script with sudo"
for option in auto_mtu trust_proxy_headers forward_proxy client_to_client peer_to_peer client_host_access local_exit dns_resolver ipv6_routed; do
  [[ ${!option} == true || ${!option} == false ]] || die "invalid saved value for $option"
done
[[ -n $domain ]] || die "--domain is required on the first deployment"
# Only an explicit interface is saved; otherwise it is detected on each run.
configured_external_interface=$external_interface
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
if $generate_ipv6 && [[ -z $ipv6_pool ]]; then
  # A random unique local prefix (RFC 4193), kept across upgrades.
  ipv6_pool=$(python3 -c 'import ipaddress, secrets; print(ipaddress.IPv6Network((b"\xfd" + secrets.token_bytes(5) + bytes(10), 64)))')
fi
ipv6_arguments=
ipv6_gateway_cidr=
if [[ -n $ipv6_pool ]]; then
  [[ -z $upstream ]] || die "IPv6 is not supported on a cascade relay (--upstream) yet"
  (( mtu >= 1280 )) || die "IPv6 needs --mtu of at least 1280"
  ipv6_layout=$(python3 - "$ipv6_pool" "$pool" <<'PY'
import ipaddress
import sys

try:
    prefix = ipaddress.IPv6Network(sys.argv[1], strict=True)
    pool = ipaddress.IPv4Network(sys.argv[2], strict=False)
except ValueError as error:
    raise SystemExit(str(error))
if prefix.prefixlen > 128 - (32 - pool.prefixlen) or prefix.prefixlen < 8:
    raise SystemExit("the IPv6 pool is too small to mirror the IPv4 pool")
if prefix.is_multicast or prefix.is_link_local or prefix.is_loopback:
    raise SystemExit("the IPv6 pool must be unicast")
print(f"{prefix.network_address + 1}/{prefix.prefixlen} {prefix}")
PY
) || die "invalid --ipv6-pool $ipv6_pool"
  read -r ipv6_gateway_cidr ipv6_pool <<<"$ipv6_layout"
  ipv6_arguments=" --ipv6-pool $ipv6_pool"
elif $ipv6_routed; then
  die "--ipv6-routed requires --ipv6 or --ipv6-pool"
fi
route_arguments=
if [[ -n $routes ]]; then
  IFS=, read -ra route_list <<<"$routes"
  for route in "${route_list[@]}"; do
    if [[ $route =~ ^[0-9A-Fa-f:]+/[0-9]{1,3}$ && $route == *:* ]]; then
      [[ -n $ipv6_pool ]] || die "IPv6 --routes entry $route needs --ipv6 or --ipv6-pool"
    else
      [[ $route =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]{1,2}$ ]] || die "invalid --routes entry: $route"
    fi
    route_arguments+=" --route $route"
  done
fi
if [[ -n $dns_domains ]]; then
  [[ -n $routes ]] || die "--dns-domains requires --routes"
  IFS=, read -ra domain_list <<<"$dns_domains"
  for split_domain in "${domain_list[@]}"; do
    [[ ${#split_domain} -le 253 &&
       $split_domain =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$ ]] ||
      die "invalid --dns-domains entry: $split_domain"
    route_arguments+=" --dns-domain $split_domain"
  done
fi
[[ $release == latest || $release =~ ^v[0-9][A-Za-z0-9._-]*$ ]] ||
  die "--release must be latest or a tag beginning with v"
federation_arguments=
if [[ -n $federation_primary ]]; then
  [[ $federation_primary =~ ^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?/?$ ]] ||
    die "--federation-primary must be an HTTPS origin such as https://primary.example.com"
  federation_primary=${federation_primary%/}
  federation_arguments=" --federation-primary $federation_primary"
  if [[ -n $upstream_ca ]]; then
    federation_arguments+=" --federation-ca /etc/porta/upstream-ca.pem"
  fi
fi
oidc_arguments=
if [[ -n $oidc_issuer || -n $oidc_client_id ]]; then
  [[ $oidc_issuer =~ ^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?(/[A-Za-z0-9._~/-]*)?$ ]] ||
    die "--oidc-issuer must be an HTTPS URL"
  [[ $oidc_client_id =~ ^[A-Za-z0-9._:@-]{1,200}$ ]] || die "--oidc-client-id is required with --oidc-issuer"
  oidc_redirect="https://$domain$([[ $port == 443 ]] || printf ':%s' "$port")/auth/oidc/callback"
  oidc_arguments=" --oidc-issuer ${oidc_issuer%/} --oidc-client-id $oidc_client_id --oidc-redirect-url $oidc_redirect"
fi
resolver_arguments=
if $dns_resolver; then
  resolver_arguments=" --dns-resolver"
  if [[ -n $dns_upstreams ]]; then
    IFS=, read -ra upstream_resolvers <<<"$dns_upstreams"
    for upstream_resolver in "${upstream_resolvers[@]}"; do
      [[ $upstream_resolver =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}(:[0-9]{1,5})?$ ]] ||
        die "invalid --dns-upstreams entry: $upstream_resolver"
      resolver_arguments+=" --dns-upstream $upstream_resolver"
    done
  fi
  if [[ -n $dns_forwards ]]; then
    IFS=, read -ra forward_specs <<<"$dns_forwards"
    for forward_spec in "${forward_specs[@]}"; do
      [[ $forward_spec =~ ^[A-Za-z0-9_.-]+=[0-9]{1,3}(\.[0-9]{1,3}){3}(:[0-9]{1,5})?$ ]] ||
        die "invalid --dns-forwards entry: $forward_spec"
      resolver_arguments+=" --dns-forward $forward_spec"
    done
  fi
  if [[ -n $dns_blocklist ]]; then
    [[ $dns_blocklist == /* && -f $dns_blocklist && $dns_blocklist =~ ^/[A-Za-z0-9_./:@+-]+$ ]] ||
      die "--dns-blocklist must name an existing absolute path"
    resolver_arguments+=" --dns-blocklist /etc/porta/dns-blocklist.txt"
  fi
else
  [[ -z $dns_upstreams && -z $dns_forwards && -z $dns_blocklist ]] ||
    die "--dns-upstreams, --dns-forwards and --dns-blocklist require --dns-resolver"
fi
exit_names=()
exit_urls=()
if [[ -n $exits ]]; then
  IFS=, read -ra exit_specs <<<"$exits"
  for exit_spec in "${exit_specs[@]}"; do
    exit_name=${exit_spec%%=*}
    exit_url=${exit_spec#*=}
    [[ $exit_spec == *=* && $exit_name =~ ^[a-z0-9-]{1,16}$ && $exit_name != local ]] ||
      die "--exits entries must be NAME=URL with a lower-case name other than local: $exit_spec"
    [[ $exit_url =~ ^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?$ ]] ||
      die "--exits $exit_name must be an HTTPS origin such as https://exit.example.com:8443"
    [[ " ${exit_names[*]} " != *" $exit_name "* ]] || die "--exits names $exit_name twice"
    exit_names+=("$exit_name")
    exit_urls+=("$exit_url")
  done
  (( ${#exit_names[@]} <= 8 )) || die "--exits supports at most 8 exits"
fi
if $local_exit && [[ -z $upstream ]]; then
  die "--local-exit requires --upstream; without it traffic already exits from this host"
fi
if [[ -z $upstream ]]; then
  [[ -z $upstream_token_file ]] || die "--upstream-token-file requires --upstream"
  [[ -z $upstream_ca || ${#exit_names[@]} -gt 0 ]] || die "--upstream-ca requires --upstream or --exits"
  if [[ -n $upstream_ca ]]; then
    [[ $upstream_ca == /* && -f $upstream_ca ]] || die "--upstream-ca must name an existing absolute path"
  fi
else
  [[ $upstream =~ ^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?/?$ ]] ||
    die "--upstream must be an HTTPS origin such as https://exit.example.com:8443"
  upstream=${upstream%/}
  [[ ${upstream#https://} != "$domain" && ${upstream#https://} != "$domain:$port" ]] ||
    die "--upstream must name another gateway, not this one"
  [[ $upstream_interface =~ ^[A-Za-z0-9_.-]{1,15}$ && $upstream_interface != "$tun_interface" ]] ||
    die "invalid --upstream-interface"
  if [[ -n $upstream_token_file ]]; then
    [[ -f $upstream_token_file && -r $upstream_token_file ]] ||
      die "--upstream-token-file must name a readable file"
  fi
  if [[ -n $upstream_ca ]]; then
    [[ $upstream_ca == /* && -f $upstream_ca ]] || die "--upstream-ca must name an existing absolute path"
  fi
fi

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

upstream_token=
if [[ -n $upstream ]]; then
  upstream_token=${PORTA_UPSTREAM_TOKEN:-}
  if [[ -n $upstream_token_file ]]; then
    upstream_token=$(<"$upstream_token_file")
  fi
  if [[ -z $upstream_token && -f /etc/porta/porta.env ]]; then
    upstream_token=$(sed -n 's/^PORTA_UPSTREAM_TOKEN=//p' /etc/porta/porta.env | tail -n 1)
  fi
  if [[ -z $upstream_token && -t 0 ]]; then
    read -rsp "Client token issued by $upstream: " upstream_token
    echo
  fi
  upstream_token=${upstream_token//[$'\r\n\t ']/}
  [[ ${#upstream_token} -ge 16 && $upstream_token =~ ^[[:graph:]]+$ ]] ||
    die "--upstream requires a client token issued by the next hop: set PORTA_UPSTREAM_TOKEN or use --upstream-token-file"
fi
federation_token=${PORTA_FEDERATION_TOKEN:-}
if [[ -z $federation_token ]] && ! $disable_federation && [[ -f /etc/porta/porta.env ]]; then
  federation_token=$(sed -n 's/^PORTA_FEDERATION_TOKEN=//p' /etc/porta/porta.env | tail -n 1)
fi
if $disable_federation; then
  [[ -z $federation_primary ]] || die "--disable-federation cannot be combined with --federation-primary"
  federation_token=
fi
if [[ -n $federation_token && ( ${#federation_token} -lt 32 || ! $federation_token =~ ^[[:graph:]]+$ ) ]]; then
  die "PORTA_FEDERATION_TOKEN must contain at least 32 printable characters"
fi
[[ -z $federation_primary || -n $federation_token ]] ||
  die "--federation-primary needs PORTA_FEDERATION_TOKEN, the token the primary uses"
exit_tokens=()
for exit_name in "${exit_names[@]}"; do
  exit_variable=PORTA_EXIT_TOKEN_$(tr 'a-z-' 'A-Z_' <<<"$exit_name")
  exit_token=${!exit_variable:-}
  if [[ -z $exit_token && -f /etc/porta/porta.env ]]; then
    exit_token=$(sed -n "s/^$exit_variable=//p" /etc/porta/porta.env | tail -n 1)
  fi
  exit_token=${exit_token//[$'\r\n\t ']/}
  [[ ${#exit_token} -ge 16 && $exit_token =~ ^[[:graph:]]+$ ]] ||
    die "exit $exit_name needs a client token issued by its gateway: set $exit_variable"
  exit_tokens+=("$exit_variable=$exit_token")
done

if [[ -z $external_interface ]]; then
  external_interface=$(ip -4 route show default | awk 'NR == 1 { for (i = 1; i <= NF; i++) if ($i == "dev") { print $(i + 1); exit } }')
fi
[[ $external_interface =~ ^[A-Za-z0-9_.:-]{1,15}$ ]] || die "could not determine a valid external interface"
[[ $external_interface != "$tun_interface" ]] || die "TUN and external interfaces must differ"
[[ -z $upstream || $external_interface != "$upstream_interface" ]] ||
  die "upstream and external interfaces must differ"
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
  build_user=${SUDO_USER:-$(id -un)}
  build_home=$(getent passwd "$build_user" | cut -d: -f6)
  cargo_binary=$(command -v cargo || true)
  if [[ -x $build_home/.cargo/bin/cargo ]]; then
    cargo_binary=$build_home/.cargo/bin/cargo
  elif [[ -z $cargo_binary ]]; then
    for candidate in /usr/local/bin/cargo /usr/bin/cargo; do
      if [[ -x $candidate ]]; then
        cargo_binary=$candidate
        break
      fi
    done
  fi
  [[ -n $cargo_binary ]] || die "Cargo with a stable Rust toolchain is required to build Porta"
  if [[ -n ${SUDO_USER:-} && $SUDO_USER != root ]]; then
    sudo -u "$SUDO_USER" env "HOME=$build_home" \
      make CARGO="$cargo_binary" build-rust-server
  else
    make CARGO="$cargo_binary" build-rust-server
  fi
  server_binary=bin/porta-server
else
  case "$(uname -m)" in
    x86_64|amd64) release_arch=amd64 ;;
    aarch64|arm64) release_arch=arm64 ;;
    *) die "GitHub releases do not provide a server binary for $(uname -m)" ;;
  esac
  release_asset=porta-server-linux-$release_arch
  release_artifacts=(
    "$release_asset"
    SHA256SUMS
    SHA256SUMS.sig
    release-signing-cert.der
    "${client_release_assets[@]}"
  )
  release_download_directory=$(mktemp -d)
  cleanup_release_download() {
    local artifact
    for artifact in "${release_artifacts[@]}" release.json github-auth-header release-public-key.pem; do
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
  release_signing_fingerprint=763e9e1dd32d2f6538149d7b86809af698d1f96c9e29b4e30ec35fc1a8969bd8
  actual_signing_fingerprint=$(openssl x509 \
    -inform DER \
    -in "$release_download_directory/release-signing-cert.der" \
    -noout -fingerprint -sha256 |
    sed -n 's/^sha256 Fingerprint=//Ip' |
    tr -d ':' |
    tr '[:upper:]' '[:lower:]')
  [[ $actual_signing_fingerprint == "$release_signing_fingerprint" ]] ||
    die "release manifest signer does not match Porta's pinned release certificate"
  release_public_key="$release_download_directory/release-public-key.pem"
  openssl x509 \
    -inform DER \
    -in "$release_download_directory/release-signing-cert.der" \
    -pubkey -noout >"$release_public_key" ||
    die "could not read the release manifest signing key"
  openssl dgst -sha256 \
    -verify "$release_public_key" \
    -signature "$release_download_directory/SHA256SUMS.sig" \
    "$release_download_directory/SHA256SUMS" >/dev/null ||
    die "release manifest signature verification failed"
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
if [[ -n $upstream ]] && ! grep -q -- '--upstream ' <<<"$server_help"; then
  die "selected server release does not support cascade relays (--upstream)"
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
pre_upgrade_backup=
service_enabled=$(systemctl is-enabled porta.service 2>/dev/null || true)
timer_enabled=$(systemctl is-enabled porta-cert-sync.timer 2>/dev/null || true)
backup_timer_enabled=$(systemctl is-enabled porta-backup.timer 2>/dev/null || true)
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
      systemctl disable --now porta-backup.timer >/dev/null 2>&1
      rollback_run restore_file porta-server /usr/local/bin/porta-server
      rollback_run restore_file server-up.sh /usr/local/libexec/porta/server-up.sh
      rollback_run restore_file server-down.sh /usr/local/libexec/porta/server-down.sh
      rollback_run restore_file sync-cert.sh /usr/local/libexec/porta/sync-cert.sh
      rollback_run restore_file 99-porta-quic.conf /etc/sysctl.d/99-porta-quic.conf
      rollback_run restore_file porta-tmpfiles.conf /etc/tmpfiles.d/porta.conf
      rollback_run restore_directory configuration /etc/porta
      rollback_run restore_directory downloads /var/lib/porta/downloads
      for state in leases clients usage; do
        rollback_run restore_file "$state.json" "/var/lib/porta/$state.json"
      done
      if [[ -n $leases_archive ]]; then
        rollback_run rm -f "$leases_archive"
      fi
      # Nothing changed, so the backup this run took is not needed.
      if [[ -n $pre_upgrade_backup ]]; then
        rollback_run rm -f "$pre_upgrade_backup"
      fi
      rollback_run restore_file porta-backup /usr/local/sbin/porta-backup
      for unit in porta.service porta-cert-sync.service porta-cert-sync.timer \
        porta-backup.service porta-backup.timer; do
        rollback_run restore_file "$unit" "/etc/systemd/system/$unit"
      done
      rollback_run systemctl daemon-reload
      rollback_run restore_enablement porta.service "$service_enabled"
      rollback_run restore_enablement porta-cert-sync.timer "$timer_enabled"
      rollback_run restore_enablement porta-backup.timer "$backup_timer_enabled"
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

# Report how this run differs from the saved configuration before any
# service is stopped.
declare -A effective_options=()
for name in "${saved_option_names[@]}"; do
  effective_options[$name]=${!name}
done
effective_options[external_interface]=$configured_external_interface
if [[ -n $upstream_ca ]]; then
  effective_options[upstream_ca]=/etc/porta/upstream-ca.pem
fi
if [[ -n $dns_blocklist ]]; then
  effective_options[dns_blocklist]=/etc/porta/dns-blocklist.txt
fi
options_changed=true
if [[ ${#saved_options[@]} -gt 0 ]]; then
  options_changed=false
  for name in "${saved_option_names[@]}"; do
    previous=${saved_options[$name]-}
    current=${effective_options[$name]}
    if [[ $previous != "$current" ]]; then
      echo "deploy: changing $name: ${previous:-(unset)} -> ${current:-(unset)}"
      options_changed=true
    fi
  done
fi
# An upgrade that changes neither options nor network helpers restarts the
# running gateway in place (systemctl reload): it keeps its sockets and
# interfaces, and clients resume within about a second.
in_place=false
if $had_active_service && ! $options_changed && ! $reset_leases &&
   grep -q '^ExecReload=' /etc/systemd/system/porta.service 2>/dev/null; then
  in_place=true
  for helper in server-up.sh server-down.sh; do
    cmp -s "scripts/$helper" "/usr/local/libexec/porta/$helper" || in_place=false
  done
fi
previous_unit=$(cat /etc/systemd/system/porta.service 2>/dev/null || true)

services_paused=true
# Quiesce writers and run the old unit's cleanup with its original helpers.
systemctl stop porta-cert-sync.timer porta-cert-sync.service >/dev/null 2>&1 || {
  if $had_active_timer || systemctl is-active --quiet porta-cert-sync.service; then
    die "could not stop certificate synchronization"
  fi
}
if $had_active_service && ! $in_place; then
  systemctl stop porta.service
fi
# A complete backup to restore when rolling back to an older release later
# (docs/operations.md); the rollback below only covers this run.
if [[ -f /var/lib/porta/clients.json ]]; then
  pre_upgrade_backup=$(PORTA_CONFIG_DIR=/etc/porta PORTA_STATE_DIR=/var/lib/porta \
    PORTA_BACKUP_DIR=/var/backups/porta bash scripts/porta-backup.sh create --keep 14) ||
    die "could not back up the gateway before upgrading it"
  echo "deploy: backed up the current gateway to $pre_upgrade_backup"
fi
backup_file /usr/local/bin/porta-server porta-server
backup_file /usr/local/sbin/porta-backup porta-backup
backup_file /usr/local/libexec/porta/server-up.sh server-up.sh
backup_file /usr/local/libexec/porta/server-down.sh server-down.sh
backup_file /usr/local/libexec/porta/sync-cert.sh sync-cert.sh
backup_file /etc/sysctl.d/99-porta-quic.conf 99-porta-quic.conf
backup_file /etc/tmpfiles.d/porta.conf porta-tmpfiles.conf
backup_directory /etc/porta configuration
backup_directory /var/lib/porta/downloads downloads
for state in leases clients usage; do
  backup_file "/var/lib/porta/$state.json" "$state.json"
done
for unit in porta.service porta-cert-sync.service porta-cert-sync.timer \
  porta-backup.service porta-backup.timer; do
  backup_file "/etc/systemd/system/$unit" "$unit"
done
deployment_started=true
install -d -m 0755 /usr/local/libexec/porta /etc/porta /etc/porta/landing /var/lib/porta/downloads
# The daemon runs as this unprivileged user with only its ambient network
# capabilities. The "!"-prefixed network helpers run as root within the same
# sandbox and keep their state in the root-only /run/porta.
service_user=porta
if ! getent passwd "$service_user" >/dev/null; then
  useradd --system --user-group --home-dir /var/lib/porta --no-create-home \
    --shell /usr/sbin/nologin "$service_user"
fi
install -m 0755 "$server_binary" /usr/local/bin/porta-server
install -m 0755 scripts/server-up.sh scripts/server-down.sh scripts/sync-cert.sh \
  /usr/local/libexec/porta/
install -d -m 0755 /usr/local/sbin
install -m 0755 scripts/porta-backup.sh /usr/local/sbin/porta-backup
install -d -m 0700 /var/backups/porta
install -m 0644 deploy/porta-backup.service deploy/porta-backup.timer /etc/systemd/system/
install -m 0644 deploy/99-porta-quic.conf /etc/sysctl.d/99-porta-quic.conf
install -m 0644 deploy/porta-tmpfiles.conf /etc/tmpfiles.d/porta.conf
systemd-tmpfiles --create /etc/tmpfiles.d/porta.conf
if ! $build_local; then
  downloads_stage=$(mktemp -d /var/lib/porta/downloads.new.XXXXXX)
  chmod 0755 "$downloads_stage"
  for artifact in "${client_release_assets[@]}" \
    SHA256SUMS SHA256SUMS.sig release-signing-cert.der; do
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
if [[ -n $upstream ]]; then
  grep -v '^PORTA_UPSTREAM_TOKEN=' "$environment_file" >"$environment_file.new" || true
  printf 'PORTA_UPSTREAM_TOKEN=%s\n' "$upstream_token" >>"$environment_file.new"
  chmod 0600 "$environment_file.new"
  mv "$environment_file.new" "$environment_file"
  unset upstream_token
fi
oidc_client_secret=${PORTA_OIDC_CLIENT_SECRET:-}
if [[ -z $oidc_client_secret && -n $oidc_arguments ]]; then
  oidc_client_secret=$(sed -n 's/^PORTA_OIDC_CLIENT_SECRET=//p' "$environment_file" | tail -n 1)
fi
grep -v '^PORTA_EXIT_TOKEN_\|^PORTA_OIDC_CLIENT_SECRET=\|^PORTA_FEDERATION_TOKEN=' "$environment_file" >"$environment_file.new" || true
if [[ -n $federation_token ]]; then
  printf 'PORTA_FEDERATION_TOKEN=%s\n' "$federation_token" >>"$environment_file.new"
fi
unset federation_token
if [[ -n $oidc_arguments && -n $oidc_client_secret ]]; then
  printf 'PORTA_OIDC_CLIENT_SECRET=%s\n' "$oidc_client_secret" >>"$environment_file.new"
fi
unset oidc_client_secret
for exit_token in "${exit_tokens[@]}"; do
  printf '%s\n' "$exit_token" >>"$environment_file.new"
done
chmod 0600 "$environment_file.new"
mv "$environment_file.new" "$environment_file"
unset exit_tokens
if [[ -n $upstream || ${#exit_names[@]} -gt 0 ]]; then
  if [[ -n $upstream_ca ]]; then
    if [[ $(realpath "$upstream_ca") != "$(realpath -m /etc/porta/upstream-ca.pem)" ]]; then
      install -m 0644 "$upstream_ca" /etc/porta/upstream-ca.pem
    fi
    upstream_ca=/etc/porta/upstream-ca.pem
  else
    rm -f /etc/porta/upstream-ca.pem
  fi
fi
if [[ -n $dns_blocklist ]]; then
  if [[ $(realpath "$dns_blocklist") != "$(realpath -m /etc/porta/dns-blocklist.txt)" ]]; then
    install -m 0644 "$dns_blocklist" /etc/porta/dns-blocklist.txt
  fi
else
  rm -f /etc/porta/dns-blocklist.txt
fi
chmod 0600 "$environment_file"
{
  echo "# Written by deploy.sh; later runs reuse these options. Edit with care."
  for name in "${saved_option_names[@]}"; do
    printf '%s=%s\n' "$name" "${effective_options[$name]}"
  done
} >"$deploy_config.new"
chmod 0600 "$deploy_config.new"
mv "$deploy_config.new" "$deploy_config"

if [[ -n $downloads_stage ]]; then
  rm -rf /var/lib/porta/downloads
  mv "$downloads_stage" /var/lib/porta/downloads
  downloads_stage=
fi
if $reset_leases && [[ -s $lease_state ]]; then
  leases_archive=$(mktemp "$lease_state.$(date -u +%Y%m%dT%H%M%SZ).XXXXXX.bak")
  mv "$lease_state" "$leases_archive"
fi
# State written by earlier root-run releases or restored by this script must
# stay writable by the service user; landing templates must stay readable.
chown -R "$service_user:$service_user" /var/lib/porta
chgrp -R "$service_user" /etc/porta/landing
chmod -R g+rX /etc/porta/landing

if [[ $tls_mode == static ]]; then
  unit_after="After=network-online.target porta-cert-sync.service docker.service"
  unit_wants="Wants=network-online.target porta-cert-sync.service"
  tls_arguments="--tls-cert /etc/porta/tls/server.crt --tls-key /etc/porta/tls/server.key"
  tls_preflight="ExecStartPre=/bin/sh -c 'test -s /etc/porta/tls/server.crt && test -r /etc/porta/tls/server.key'"
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
if { (( port < 1024 || admin_port < 1024 )) || $dns_resolver; } && [[ $capabilities != *CAP_NET_BIND_SERVICE* ]]; then
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
upstream_arguments=
network_up_options=
if [[ -n $upstream ]]; then
  upstream_arguments="--upstream $upstream --upstream-interface $upstream_interface"
  network_up_options=" --upstream-interface $upstream_interface"
fi
if [[ -n $upstream || ${#exit_names[@]} -gt 0 ]]; then
  # Every next hop enrolls this gateway with the same device key.
  upstream_arguments+="${upstream_arguments:+ }--upstream-identity /var/lib/porta/upstream-identity.json"
  if [[ -n $upstream_ca ]]; then
    upstream_arguments+=" --upstream-ca /etc/porta/upstream-ca.pem"
  fi
fi
for index in "${!exit_names[@]}"; do
  upstream_arguments+=" --exit ${exit_names[$index]}=${exit_urls[$index]}"
  network_up_options+=" --exit-interface porta-up$((index + 1))"
done
if $local_exit; then
  upstream_arguments+=" --local-exit"
  network_up_options+=" --local-exit"
fi
client_to_client_argument=
if $client_to_client; then
  client_to_client_argument=" --client-to-client"
fi
if $peer_to_peer; then
  client_to_client_argument+=" --peer-to-peer"
fi
if $client_host_access; then
  network_up_options+=" --client-host-access"
fi
if [[ -n $ipv6_pool ]]; then
  network_up_options+=" --ipv6 $ipv6_gateway_cidr $ipv6_pool"
  if $ipv6_routed; then
    network_up_options+=" --ipv6-routed"
  fi
fi

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
User=$service_user
Group=$service_user
EnvironmentFile=/etc/porta/porta.env
$tls_preflight
ExecStart=/usr/local/bin/porta-server --listen :$port --admin-listen 127.0.0.1:$admin_port $tls_arguments $forward_proxy_argument $trust_proxy_argument $auto_mtu_argument $upstream_arguments --landing-template-dir /etc/porta/landing --client-downloads /var/lib/porta/downloads --client-registry /var/lib/porta/clients.json --interface $tun_interface --egress-interface $external_interface --pool $pool --lease-state /var/lib/porta/leases.json --dns $dns$route_arguments$resolver_arguments$client_to_client_argument$oidc_arguments$federation_arguments$ipv6_arguments --mtu $mtu --json-logs
ExecStartPost=!/bin/bash -c 'for i in \$(seq 1 50); do /usr/sbin/ip link show dev $tun_interface >/dev/null 2>&1 && exec /usr/local/libexec/porta/server-up.sh $tun_interface $gateway_cidr $pool $external_interface $port$network_up_options; sleep 0.1; done; exit 1'
ExecStopPost=!/usr/local/libexec/porta/server-down.sh $tun_interface $external_interface
# Restarts in place for upgrades, keeping sockets, interfaces and leases.
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=2
TimeoutStopSec=15
LimitNOFILE=65536
UMask=0077
StateDirectory=porta
ReadWritePaths=/run/porta
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
ExecStart=/usr/local/libexec/porta/sync-cert.sh $certificate $private_key /etc/porta/tls $service_user
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
systemctl enable --now porta-backup.timer >/dev/null
if [[ $tls_mode == static ]]; then
  systemctl enable porta-cert-sync.timer >/dev/null
  systemctl start porta-cert-sync.service
fi
if $in_place && [[ $(cat /etc/systemd/system/porta.service) == "$previous_unit" ]]; then
  echo "deploy: restarting the running gateway in place"
  systemctl reload porta.service
else
  systemctl restart porta.service
fi
if [[ $tls_mode == static ]]; then
  systemctl start porta-cert-sync.timer
fi

for _ in $(seq 1 30); do
  if curl --silent --show-error --fail --noproxy '*' --connect-timeout 5 --max-time 10 "http://127.0.0.1:$admin_port/readyz" >/dev/null; then
    break
  fi
  sleep 1
done
if ! curl --silent --show-error --fail --noproxy '*' --connect-timeout 5 --max-time 10 "http://127.0.0.1:$admin_port/readyz" >/dev/null; then
  readiness_report=$(curl --silent --noproxy '*' --connect-timeout 5 --max-time 10 \
    "http://127.0.0.1:$admin_port/readyz" 2>/dev/null || true)
  if [[ -n $readiness_report ]]; then
    echo "deploy: readiness report: $readiness_report" >&2
  fi
  if [[ -n $upstream ]]; then
    echo "deploy: a relay is ready only after $upstream accepts its token and device" >&2
  fi
  die "gateway started but did not become ready; see: sudo journalctl -u porta -n 50"
fi
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

selectable_exits=
if $local_exit || [[ -z $upstream && ${#exit_names[@]} -gt 0 ]]; then
  selectable_exits=local
fi
for exit_name in "${exit_names[@]}"; do
  selectable_exits+="${selectable_exits:+, }$exit_name"
done

cat <<EOF
Porta is ready.

Direct endpoint: https://$domain:$port
Transports:      HTTP/2 over TCP $port and HTTP/3 MASQUE over UDP $port
Forward proxy:   $([[ $forward_proxy == true ]] && echo "enabled (HTTPS CONNECT on port 443 only)" || echo "disabled")
TLS mode:        $tls_mode
Server source:   $([[ $build_local == true ]] && echo "local checkout" || echo "GitHub release $release")
Exit traffic:    $([[ -n $upstream ]] && echo "relayed through $upstream via $upstream_interface" || echo "this host via $external_interface")
Selectable exits: ${selectable_exits:-none}
Client-to-client: $([[ $client_to_client == true ]] && echo "allowed within $pool" || echo "blocked")
Backups:         daily to /var/backups/porta (porta-backup.timer); restore with sudo porta-backup restore
Direct paths:    $([[ $peer_to_peer == true ]] && echo "offered to HTTP/3 split-tunnel clients" || echo "off (client traffic goes through this gateway)")
Client IPv6:     $([[ -n $ipv6_pool ]] && echo "$ipv6_pool, $([[ $ipv6_routed == true ]] && echo "routed" || echo "masqueraded") through $external_interface" || echo "off (clients keep IPv6 off the tunnel)")
Host services:   $([[ $client_host_access == true ]] && echo "reachable from clients" || echo "ping and DNS only from clients")
Client DNS:      $([[ $dns_resolver == true ]] && echo "built-in resolver on ${gateway_cidr%/*} with names under porta.internal" || echo "$dns")
Client routing:  $([[ -n $routes ]] && echo "split tunnel: ${routes//,/, }${dns_domains:+ (DNS for ${dns_domains//,/, })}" || echo "full tunnel")
Accounts:        $([[ -n $federation_primary ]] && echo "mirrored from $federation_primary (read-only here)" || echo "managed here")
Admin endpoint:  http://127.0.0.1:$admin_port
Admin sign-in:   https://$domain$([[ $port == 443 ]] || printf ':%s' "$port")/admin/sign-in$([[ -n $oidc_arguments ]] && echo " (single sign-on through $oidc_issuer)")
Browser portal:  https://$domain:$port
Admin token:     sudo sed -n 's/^PORTA_ADMIN_TOKEN=//p' /etc/porta/porta.env
Initial client:  sudo sed -n 's/^PORTA_TOKEN=//p' /etc/porta/porta.env
$client_download_summary
Ensure both TCP and UDP $port are allowed by the host and cloud firewalls.
EOF
