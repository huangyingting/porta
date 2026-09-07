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

sudo -n unshare --net -- bash -euo pipefail -c '
binary=$1
runtime_directory=$(mktemp -d)
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
rmdir "$fake_bin" "$runtime_directory"
' _ "$binary"
