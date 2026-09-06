#!/usr/bin/env bash
set -euo pipefail

for command in sudo unshare ip nft sysctl grep mktemp; do
  command -v "$command" >/dev/null || {
    echo "missing required command: $command" >&2
    exit 1
  }
done

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
sudo -n unshare --net -- bash -euo pipefail -c '
repository_root=$1
runtime_directory=$(mktemp -d)
export PORTA_RUNTIME_DIRECTORY="$runtime_directory"
cleanup() {
  status=$?
  trap - EXIT
  "$repository_root/scripts/server-down.sh" porta0 eth0 || status=1
  rm -f "$runtime_directory/ip-forward-porta0" "$runtime_directory/docker-rules-porta0"
  rmdir "$runtime_directory" || status=1
  exit "$status"
}
trap cleanup EXIT

ip link add porta0 type dummy
ip link add eth0 type dummy
ip link set dev eth0 up

"$repository_root/scripts/server-up.sh" \
  porta0 10.66.0.1/24 10.66.0.0/24 eth0 8443

forward_rules=$(nft list table ip porta)
guard_rules=$(nft list table inet porta_guard)
grep -Fq "iifname \"porta0\" oifname \"eth0\" accept" <<<"$forward_rules"
grep -Fq "ip saddr 10.66.0.0/24 masquerade" <<<"$forward_rules"
grep -Fq "tcp dport 8443" <<<"$guard_rules"
grep -Fq "meter tcp4 size 65535" <<<"$guard_rules"
grep -Fq "limit rate over 200/second burst 400 packets" <<<"$guard_rules"
grep -Fq "meter udp6 size 65535" <<<"$guard_rules"
grep -Fq "limit rate over 500/second burst 1000 packets" <<<"$guard_rules"

"$repository_root/scripts/server-up.sh" \
  porta0 10.66.0.1/24 10.66.0.0/24 eth0 8443
"$repository_root/scripts/server-down.sh" porta0 eth0
rmdir "$runtime_directory"
trap - EXIT

if nft list table ip porta >/dev/null 2>&1 ||
   nft list table inet porta_guard >/dev/null 2>&1; then
  echo "Porta nftables tables remain after cleanup" >&2
  exit 1
fi
' _ "$repository_root"
