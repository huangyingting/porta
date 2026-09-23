#!/usr/bin/env bash
set -euo pipefail

for command in sudo unshare ip nft mount umount; do
  command -v "$command" >/dev/null || {
    echo "missing required command: $command" >&2
    exit 1
  }
done

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
work=$repository_root/.native-client-build-$$
mkdir -m 0700 "$work"
trap 'rm -f "$work/native-client-network"; rmdir "$work"' EXIT
(
  cd "$repository_root"
  CGO_ENABLED=0 "${GO:-go}" build -o "$work/native-client-network" ./scripts/native-client-network
)

sudo -n unshare --net --mount --propagation private -- bash -euo pipefail -c '
binary=$1
runtime_directory="$PWD/.native-client-runtime-$$"
mkdir -m 0700 "$runtime_directory"
fake_bin="$runtime_directory/bin"
state_path="$runtime_directory/network-state.json"
mounted_etc=false
mounted_run=false
cleanup() {
  status=$?
  trap - EXIT
  if $mounted_etc; then umount /etc || status=1; fi
  if $mounted_run; then umount /run || status=1; fi
  rm -rf -- "$runtime_directory"
  exit "$status"
}
trap cleanup EXIT
mkdir -p "$fake_bin" "$runtime_directory/etc" "$runtime_directory/run/systemd/resolve"
printf "nameserver 127.0.0.53\n" >"$runtime_directory/run/systemd/resolve/stub-resolv.conf"
ln -s /run/systemd/resolve/stub-resolv.conf "$runtime_directory/etc/resolv.conf"
mount --bind "$runtime_directory/run" /run
mounted_run=true
mount --bind "$runtime_directory/etc" /etc
mounted_etc=true
cat >"$fake_bin/resolvectl" <<'"'"'EOF'"'"'
#!/usr/bin/env bash
set -euo pipefail
case "${1:-}" in
  status|revert|default-route) exit 0 ;;
  dns|domain)
    if [[ $# == 2 ]]; then
      printf "Link 2 (%s):\n" "$2"
    fi
    ;;
  *) exit 2 ;;
esac
EOF
chmod 0755 "$fake_bin/resolvectl"
export PATH="$fake_bin:/usr/sbin:/usr/bin:/sbin:/bin"

ip link set dev lo up
ip link add uplink type dummy
ip address add 192.0.2.2/24 dev uplink
ip link set dev uplink up
ip route add default via 192.0.2.1 dev uplink onlink

PORTA_NATIVE_CLIENT_NETWORK_TEST=1 "$binary" "$state_path"
if ip link show dev porta0 >/dev/null 2>&1; then
  echo "Porta TUN remains after native client network test" >&2
  exit 1
fi
if nft list tables | grep -q porta_; then
  echo "Porta nftables state remains after native client network test" >&2
  exit 1
fi
if ip -4 route show proto 186 | grep -q .; then
  echo "Porta-owned routes remain after native client network test" >&2
  exit 1
fi
' _ "$work/native-client-network"
