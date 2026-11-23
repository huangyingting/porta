#!/usr/bin/env bash
# Installs the Porta Linux desktop app: the root client service it controls,
# the porta-client group whose members may use it, and the menu entry.
#
# Usage: sudo scripts/install-linux-desktop.sh [--client PATH] [--desktop PATH] [--user USER]
#   --client PATH   porta-client binary (default: bin/porta-client)
#   --desktop PATH  porta-desktop binary (default: bin/porta-desktop)
#   --user USER     user to allow to control the service (default: $SUDO_USER)
set -euo pipefail

die() {
  echo "install-linux-desktop: $*" >&2
  exit 1
}

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
client=$repository_root/bin/porta-client
desktop=$repository_root/bin/porta-desktop
user=${SUDO_USER:-}
while [[ $# -gt 0 ]]; do
  case "$1" in
    --client) [[ $# -ge 2 ]] || die "--client requires a path"; client=$2; shift 2 ;;
    --desktop) [[ $# -ge 2 ]] || die "--desktop requires a path"; desktop=$2; shift 2 ;;
    --user) [[ $# -ge 2 ]] || die "--user requires a name"; user=$2; shift 2 ;;
    --help|-h) sed -n '2,9p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done
[[ $EUID -eq 0 ]] || die "run this script with sudo"
for binary in "$client" "$desktop"; do
  [[ -f $binary && -x $binary ]] || die "missing executable: $binary (build with: make build build-linux-desktop)"
done
[[ -z $user || $user =~ ^[a-z_][a-z0-9_.-]{0,31}$ ]] || die "invalid user name: $user"
if [[ -n $user ]] && ! getent passwd "$user" >/dev/null; then
  die "user $user does not exist"
fi

install -m 0755 "$client" /usr/local/bin/porta-client
install -m 0755 "$desktop" /usr/local/bin/porta-desktop
if ! getent group porta-client >/dev/null; then
  groupadd --system porta-client
fi
if [[ -n $user ]]; then
  usermod --append --groups porta-client "$user"
fi
install -m 0644 "$repository_root/deploy/porta-client.service" /etc/systemd/system/porta-client.service
install -d -m 0755 /usr/share/applications /usr/share/icons/hicolor/256x256/apps
install -m 0644 "$repository_root/deploy/porta-desktop.desktop" /usr/share/applications/porta-desktop.desktop
install -m 0644 "$repository_root/deploy/porta.png" /usr/share/icons/hicolor/256x256/apps/porta.png
systemctl daemon-reload
systemctl enable porta-client.service >/dev/null
systemctl restart porta-client.service

cat <<SUMMARY
Porta desktop is installed.

Service:  porta-client.service (root; profiles in /var/lib/porta-client)
App:      Porta in the applications menu, or run porta-desktop
Access:   members of the porta-client group${user:+ (added $user; sign out and in again)}
SUMMARY
