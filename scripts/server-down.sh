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

for command in ip nft grep; do
  command -v "$command" >/dev/null || {
    echo "required cleanup command not found: $command" >&2
    exit 1
  }
done
state_directory=${PORTA_RUNTIME_DIRECTORY:-/run/porta}
[[ $state_directory == /* && $state_directory != *[$'\n\r\t ']* ]] || {
  echo "invalid Porta runtime directory" >&2
  exit 2
}
ip_forward_state="$state_directory/ip-forward-$tun_interface"
ip6_forward_state="$state_directory/ip6-forward-$tun_interface"
accept_ra_state="$state_directory/accept-ra-$tun_interface"
docker_rules_state="$state_directory/docker-rules-$tun_interface"
docker6_rules_state="$state_directory/docker6-rules-$tun_interface"

docker_tool=iptables
remove_docker_rule() {
  while true; do
    if "$docker_tool" -w -C DOCKER-USER "$@" 2>/dev/null; then
      "$docker_tool" -w -D DOCKER-USER "$@" || return
      continue
    else
      check_status=$?
    fi
    [[ $check_status -eq 1 ]] && return 0
    return "$check_status"
  done
}

docker_tracked=false
docker_state_valid=true
docker_interfaces=()
if [[ -e $docker_rules_state ]]; then
  docker_tracked=true
  mapfile -t docker_interfaces <"$docker_rules_state"
  if [[ ${#docker_interfaces[@]} -eq 0 ]]; then
    echo "saved Docker rule state is empty" >&2
    status=1
    docker_state_valid=false
  fi
fi
if ! $docker_tracked && [[ -n $external_interface ]]; then
  docker_interfaces=("$external_interface")
elif $docker_tracked && [[ -n $external_interface ]]; then
  docker_interfaces+=("$external_interface")
fi
for tracked_external_interface in "${docker_interfaces[@]}"; do
  if [[ ! $tracked_external_interface =~ ^[A-Za-z0-9_.:-]{1,15}$ ]]; then
    echo "saved Docker rule interface is invalid" >&2
    status=1
    docker_state_valid=false
  fi
done
docker_cleanup_complete=false
if $docker_tracked && ! command -v iptables >/dev/null; then
  echo "iptables is required to remove Porta Docker rules" >&2
  status=1
elif $docker_state_valid && [[ ${#docker_interfaces[@]} -gt 0 ]] && command -v iptables >/dev/null; then
  if ! docker_rules=$(iptables -w -S); then
    echo "could not inspect Porta Docker rules" >&2
    status=1
  elif ! grep -Fxq -- '-N DOCKER-USER' <<<"$docker_rules"; then
    docker_cleanup_complete=true
  else
    docker_cleanup_complete=true
    for tracked_external_interface in "${docker_interfaces[@]}"; do
      if ! remove_docker_rule -i "$tun_interface" -o "$tracked_external_interface" -m comment --comment porta -j ACCEPT; then
        status=1
        docker_cleanup_complete=false
      fi
      if ! remove_docker_rule -i "$tracked_external_interface" -o "$tun_interface" -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment porta -j ACCEPT; then
        status=1
        docker_cleanup_complete=false
      fi
    done
  fi
fi
if $docker_tracked && $docker_cleanup_complete; then
  rm -f "$docker_rules_state"
fi
if [[ -e $docker6_rules_state ]]; then
  ipv6_docker_interface=$(<"$docker6_rules_state")
  if [[ ! $ipv6_docker_interface =~ ^[A-Za-z0-9_.:-]{1,15}$ ]]; then
    echo "saved IPv6 Docker rule interface is invalid" >&2
    status=1
  elif ! command -v ip6tables >/dev/null; then
    echo "ip6tables is required to remove Porta IPv6 Docker rules" >&2
    status=1
  elif ! docker6_rules=$(ip6tables -w -S); then
    echo "could not inspect Porta IPv6 Docker rules" >&2
    status=1
  else
    docker_tool=ip6tables
    if ! grep -Fxq -- '-N DOCKER-USER' <<<"$docker6_rules" ||
       { remove_docker_rule -i "$tun_interface" -o "$ipv6_docker_interface" -m comment --comment porta -j ACCEPT &&
         remove_docker_rule -i "$ipv6_docker_interface" -o "$tun_interface" -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment porta -j ACCEPT; }; then
      rm -f "$docker6_rules_state"
    else
      status=1
    fi
    docker_tool=iptables
  fi
fi
nft_cleanup=
if nft_tables=$(nft list tables); then
  for table in 'ip porta' 'ip6 porta' 'inet porta_guard'; do
    if grep -Fxq "table $table" <<<"$nft_tables"; then
      nft_cleanup+="delete table $table"$'\n'
    fi
  done
else
  echo "could not inspect Porta nftables tables" >&2
  status=1
fi
if [[ -n $nft_cleanup ]] && ! printf '%s' "$nft_cleanup" | nft -f -; then
  status=1
fi
# Remove cascade relay policy routing installed by server-up.sh, if any.
relay_table=10066
relay_priority=10066
relay_rule_present() {
  local rules line
  rules=$(ip -4 rule show) || return 2
  while IFS= read -r line; do
    [[ $line == "$relay_priority:"*" iif $tun_interface lookup $relay_table"* ]] && return 0
  done <<<"$rules"
  return 1
}
relay_rules_removed=false
for _ in 1 2 3 4 5 6 7 8; do
  if relay_rule_present; then
    ip -4 rule del priority "$relay_priority" iif "$tun_interface" lookup "$relay_table" || break
  else
    [[ $? -eq 1 ]] && relay_rules_removed=true
    break
  fi
done
if ! $relay_rules_removed; then
  echo "could not remove Porta relay routing rules" >&2
  status=1
fi
ip -4 route flush table "$relay_table" 2>/dev/null || true
# Named exit tables, and any per-lease exit rules a stopped daemon left.
for ((exit_table = 10067; exit_table < 10075; exit_table++)); do
  ip -4 route flush table "$exit_table" 2>/dev/null || true
done
exit_rules_removed=false
for _ in $(seq 1 1024); do
  if ! exit_rule=$(ip -4 rule show priority 10065 iif "$tun_interface"); then
    break
  fi
  if [[ -z $exit_rule ]]; then
    exit_rules_removed=true
    break
  fi
  ip -4 rule del priority 10065 iif "$tun_interface" || break
done
if ! $exit_rules_removed; then
  echo "could not remove Porta exit selection rules" >&2
  status=1
fi
if links=$(ip -o link show); then
  while read -r index name rest; do
    name=${name%:}
    name=${name%%@*}
    if [[ $name == "$tun_interface" ]]; then
      ip link set dev "$tun_interface" down || status=1
      break
    fi
  done <<<"$links"
else
  echo "could not inspect Porta interface state" >&2
  status=1
fi
if [[ -e $ip_forward_state ]]; then
  if ! command -v sysctl >/dev/null; then
    echo "sysctl is required to restore IPv4 forwarding" >&2
    status=1
  else
    original_ip_forward=$(<"$ip_forward_state")
    current_ip_forward=$(sysctl -n net.ipv4.ip_forward) || current_ip_forward=
    if [[ $original_ip_forward != 0 && $original_ip_forward != 1 ||
          $current_ip_forward != 0 && $current_ip_forward != 1 ]]; then
      echo "could not validate the IPv4 forwarding state" >&2
      status=1
    elif [[ $current_ip_forward == 1 ]] &&
         ! sysctl -w "net.ipv4.ip_forward=$original_ip_forward"; then
      status=1
    else
      rm -f "$ip_forward_state"
    fi
  fi
fi
if [[ -e $ip6_forward_state ]]; then
  if ! command -v sysctl >/dev/null; then
    echo "sysctl is required to restore IPv6 forwarding" >&2
    status=1
  else
    original_ip6_forward=$(<"$ip6_forward_state")
    current_ip6_forward=$(sysctl -n net.ipv6.conf.all.forwarding) || current_ip6_forward=
    if [[ $original_ip6_forward != 0 && $original_ip6_forward != 1 ||
          $current_ip6_forward != 0 && $current_ip6_forward != 1 ]]; then
      echo "could not validate the IPv6 forwarding state" >&2
      status=1
    elif [[ $current_ip6_forward == 1 ]] &&
         ! sysctl -w "net.ipv6.conf.all.forwarding=$original_ip6_forward"; then
      status=1
    else
      rm -f "$ip6_forward_state"
    fi
  fi
fi
if [[ -e $accept_ra_state ]]; then
  read -r ra_interface original_accept_ra <"$accept_ra_state" || true
  if [[ $original_accept_ra == 1 && $ra_interface =~ ^[A-Za-z0-9_.:-]{1,15}$ ]]; then
    # Leave a value something else changed since.
    current_accept_ra=$(sysctl -n "net/ipv6/conf/$ra_interface/accept_ra" 2>/dev/null) || current_accept_ra=
    if [[ $current_accept_ra == 2 ]] && ! sysctl -w "net/ipv6/conf/$ra_interface/accept_ra=1"; then
      status=1
    fi
  fi
  if [[ $status -eq 0 ]]; then
    rm -f "$accept_ra_state"
  fi
fi
if [[ $status -eq 0 ]]; then
  echo "removed Porta networking and restored host forwarding state for $tun_interface"
else
  echo "could not completely remove Porta networking for $tun_interface" >&2
fi
exit "$status"
