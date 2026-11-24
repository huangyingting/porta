#!/usr/bin/env bash
# Backs up and restores a Porta gateway's configuration and state:
# accounts and devices, leases, usage, administrators, the audit log, the
# relay identity, ACME certificates, TLS files and /etc/porta (including
# the tokens in porta.env). Client downloads are left out; deploy.sh
# fetches them again.
#
# Usage:
#   sudo porta-backup create [--keep N]   write a new archive (default keep: 14)
#   sudo porta-backup list                show archives, newest first
#   sudo porta-backup verify ARCHIVE      check an archive's checksums
#   sudo porta-backup restore ARCHIVE     stop Porta, restore, start and wait
#                                         until it is ready
#
# Archives are root-only .tar.gz files in /var/backups/porta. They hold every
# secret the gateway has; encrypt them before copying them off the host.
set -euo pipefail

config_directory=${PORTA_CONFIG_DIR:-/etc/porta}
state_directory=${PORTA_STATE_DIR:-/var/lib/porta}
backup_directory=${PORTA_BACKUP_DIR:-/var/backups/porta}
service=porta.service
ready_url=${PORTA_READY_URL:-}

cleanup=()
trap 'rm -rf "${cleanup[@]}"' EXIT
die() { echo "porta-backup: $*" >&2; exit 1; }
usage() { sed -n '2,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//'; exit "${1:-0}"; }

[[ ${PORTA_BACKUP_ALLOW_NONROOT:-} == 1 || $EUID -eq 0 ]] || die "run with sudo"
umask 077

# State that is worth restoring; everything else under the state directory
# (downloads, deploy rollback leftovers) is reproducible.
state_entries() {
  local entry path
  for entry in clients.json leases.json usage.json admins.json audit.log audit.log.* \
    upstream-identity.json client-identity.json acme; do
    compgen -G "$state_directory/$entry" >/dev/null || continue
    for path in "$state_directory"/$entry; do
      [[ -e $path && ! $path == *.lock ]] && printf '%s\n' "${path#"$state_directory"/}"
    done
  done
}

admin_url() {
  if [[ -n $ready_url ]]; then
    printf '%s' "$ready_url"
    return
  fi
  local port=9090
  if [[ -f /etc/systemd/system/$service ]]; then
    port=$(sed -n 's/.*--admin-listen 127\.0\.0\.1:\([0-9]*\).*/\1/p' "/etc/systemd/system/$service" | head -n 1)
    port=${port:-9090}
  fi
  printf 'http://127.0.0.1:%s/readyz' "$port"
}

create() {
  local keep=14
  while [[ $# -gt 0 ]]; do
    case $1 in
      --keep) keep=${2:-}; shift 2 ;;
      --keep=*) keep=${1#*=}; shift ;;
      *) die "unknown option $1" ;;
    esac
  done
  [[ $keep =~ ^[1-9][0-9]*$ ]] || die "--keep must be a positive number"
  [[ -d $config_directory ]] || die "missing $config_directory"
  [[ -d $state_directory ]] || die "missing $state_directory"
  install -d -m 0700 "$backup_directory"
  local stamp staging archive
  stamp=$(date -u +%Y%m%dT%H%M%SZ)
  staging=$(mktemp -d "$backup_directory/.staging.XXXXXX")
  cleanup+=("$staging")
  # The gateway replaces its JSON files atomically, so each copy is one
  # complete version of its file.
  mkdir -p "$staging/config" "$staging/state"
  cp -a "$config_directory/." "$staging/config/"
  local entry
  while IFS= read -r entry; do
    mkdir -p "$staging/state/$(dirname "$entry")"
    cp -a "$state_directory/$entry" "$staging/state/$entry"
  done < <(state_entries)
  {
    echo "format=1"
    echo "created=$stamp"
    echo "host=$(hostname)"
    if [[ -x /usr/local/bin/porta-server ]]; then
      echo "server=$(/usr/local/bin/porta-server --version 2>/dev/null | head -n 1)"
    fi
  } >"$staging/MANIFEST"
  (cd "$staging" && find config state MANIFEST -type f -print0 | sort -z | xargs -0 sha256sum) \
    >"$staging/SHA256SUMS"
  archive="$backup_directory/porta-$stamp.tar.gz"
  tar -C "$staging" -czpf "$archive.partial" MANIFEST SHA256SUMS config state
  mv "$archive.partial" "$archive"
  chmod 0600 "$archive"
  echo "$archive"
  # Keep the newest archives.
  local old
  while IFS= read -r old; do
    rm -f "$old"
  done < <(list_archives | tail -n "+$((keep + 1))")
}

list_archives() {
  compgen -G "$backup_directory/porta-*.tar.gz" >/dev/null || return 0
  ls -1t "$backup_directory"/porta-*.tar.gz
}

# Extracts and checks ARCHIVE into a new directory, printing its path.
unpack() {
  local archive=$1 directory
  [[ -f $archive ]] || die "no archive $archive"
  directory=$(mktemp -d "${TMPDIR:-/tmp}/porta-restore.XXXXXX")
  if ! tar -C "$directory" -xzpf "$archive" 2>/dev/null; then
    rm -rf "$directory"
    die "cannot read $archive"
  fi
  local member
  for member in MANIFEST SHA256SUMS config state; do
    [[ -e $directory/$member ]] || { rm -rf "$directory"; die "$archive is not a Porta backup"; }
  done
  grep -qx 'format=1' "$directory/MANIFEST" || { rm -rf "$directory"; die "unsupported backup format"; }
  if ! (cd "$directory" && sha256sum --quiet --strict -c SHA256SUMS) >&2; then
    rm -rf "$directory"
    die "$archive failed its checksums"
  fi
  printf '%s' "$directory"
}

verify() {
  [[ $# -eq 1 ]] || usage 2
  local directory
  directory=$(unpack "$1")
  cleanup+=("$directory")
  sed 's/^/  /' "$directory/MANIFEST"
  echo "$(grep -c . "$directory/SHA256SUMS") files verified"
}

restore() {
  [[ $# -eq 1 ]] || usage 2
  local directory stamp aside
  directory=$(unpack "$1")
  cleanup+=("$directory")
  stamp=$(date -u +%Y%m%dT%H%M%SZ)
  aside="$state_directory/restore-replaced-$stamp"
  echo "stopping $service"
  systemctl stop "$service"
  # What the restore replaces is kept, so a mistaken restore is undoable.
  mkdir -p "$aside/config" "$aside/state"
  cp -a "$config_directory/." "$aside/config/"
  local entry
  while IFS= read -r entry; do
    mkdir -p "$aside/state/$(dirname "$entry")"
    mv "$state_directory/$entry" "$aside/state/$entry"
  done < <(state_entries)
  cp -a "$directory/config/." "$config_directory/"
  cp -a "$directory/state/." "$state_directory/"
  if id porta >/dev/null 2>&1; then
    while IFS= read -r entry; do
      chown -R porta:porta "$state_directory/$entry"
    done < <(state_entries)
  fi
  echo "starting $service"
  systemctl start "$service"
  local url
  url=$(admin_url)
  for _ in $(seq 1 60); do
    if curl -fsS --max-time 2 "$url" >/dev/null 2>&1; then
      echo "restored $(sed -n 's/^created=//p' "$directory/MANIFEST") backup; previous state kept in $aside"
      return 0
    fi
    sleep 1
  done
  die "$service did not become ready after the restore; previous state is in $aside"
}

case ${1:-} in
  create) shift; create "$@" ;;
  list) list_archives ;;
  verify) shift; verify "$@" ;;
  restore) shift; restore "$@" ;;
  -h|--help|help) usage ;;
  *) usage 2 ;;
esac
