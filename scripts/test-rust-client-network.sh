#!/usr/bin/env bash
set -euo pipefail

for command in sudo unshare ip nft mktemp; do
  command -v "$command" >/dev/null || {
    echo "missing required command: $command" >&2
    exit 1
  }
done

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cargo="${CARGO:-$HOME/.cargo/bin/cargo}"
"$cargo" build \
  --manifest-path "$repository_root/rust/Cargo.toml" \
  --package porta-client-rust \
  --example linux-network-cycle \
  --locked
binary="$repository_root/rust/target/debug/examples/linux-network-cycle"
# Automatic Linux networking requires systemd-resolved's stub. The test gives
# itself one in a private mount namespace (an overlay on /etc whose
# resolv.conf links to it), so it does not depend on how the host resolves
# names and leaves the host's /etc untouched.
sudo -n unshare --net --mount --propagation private -- bash -euo pipefail -c '
binary=$1
runtime_directory=$(mktemp -d)
mkdir -p "$runtime_directory/etc-upper" "$runtime_directory/etc-work"
mount -t overlay porta-etc \
  -o "lowerdir=/etc,upperdir=$runtime_directory/etc-upper,workdir=$runtime_directory/etc-work" /etc
mkdir -p /run/systemd/resolve
mount -t tmpfs porta-resolve /run/systemd/resolve
printf "nameserver 127.0.0.53\noptions edns0 trust-ad\n" >/run/systemd/resolve/stub-resolv.conf
ln -sfn /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
fake_bin="$runtime_directory/bin"
state_path="$runtime_directory/network-state.json"
mkdir -p "$fake_bin"
cat > "$fake_bin/resolvectl" <<'"'"'EOF'"'"'
#!/usr/bin/env bash
set -euo pipefail
case "${1:-}" in
  status) exit 0 ;;
  dns|domain)
    if [[ $# == 2 ]]; then
      printf "Link 2 (%s):\n" "$2"
    fi
    ;;
esac
EOF
chmod +x "$fake_bin/resolvectl"
export PATH="$fake_bin:/usr/sbin:/usr/bin:/sbin:/bin"

ip link set dev lo up
ip link add uplink type dummy
ip address add 192.0.2.2/24 dev uplink
ip link set dev uplink up
ip route add default via 192.0.2.1 dev uplink onlink

"$binary" "$state_path"
if ip link show dev porta0 >/dev/null 2>&1; then
  echo "Porta TUN remains after native network test" >&2
  exit 1
fi
if nft list tables | grep -q porta_; then
  echo "Porta nftables state remains after native network test" >&2
  exit 1
fi
rm -f "$fake_bin/resolvectl" "$state_path.lock"
rmdir "$fake_bin"
umount /etc /run/systemd/resolve
rm -rf "$runtime_directory"
' _ "$binary"
