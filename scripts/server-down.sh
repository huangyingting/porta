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
docker_rules_state="$state_directory/docker-rules-$tun_interface"

remove_docker_rule() {
  while true; do
    if iptables -w -C DOCKER-USER "$@" 2>/dev/null; then
      iptables -w -D DOCKER-USER "$@" || return
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
nft_cleanup=
if nft_tables=$(nft list tables); then
  for table in 'ip porta' 'inet porta_guard'; do
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
if [[ $status -eq 0 ]]; then
  echo "removed Porta networking and restored host forwarding state for $tun_interface"
else
  echo "could not completely remove Porta networking for $tun_interface" >&2
fi
exit "$status"
