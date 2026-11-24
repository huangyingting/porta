#!/usr/bin/env bash
# Installs the TPM vendor CA certificates that Microsoft publishes in
# TrustedTpm.cab, so that the gateway (--tpm-ca-dir) can verify that device
# keys live in a TPM. It keeps the vendors' roots and their endorsement key
# intermediates, and skips Microsoft's own AIK service CAs, which do not
# issue endorsement key certificates.
#
# Usage: sudo porta-tpm-cas [DIRECTORY]      (default /var/lib/porta/tpm-ca)
#
# PORTA_TPM_CAS_CAB names a TrustedTpm.cab to use instead of downloading it.
set -euo pipefail

directory=${1:-/var/lib/porta/tpm-ca}
source_url='https://go.microsoft.com/fwlink/?linkid=2097925'

die() { echo "porta-tpm-cas: $*" >&2; exit 1; }
[[ $directory == /* && $directory != / ]] || die "the directory must be an absolute path"
command -v cabextract >/dev/null || die "cabextract is required (apt-get install cabextract)"

work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
if [[ -n ${PORTA_TPM_CAS_CAB:-} ]]; then
  cp -- "$PORTA_TPM_CAS_CAB" "$work/TrustedTpm.cab"
else
  curl -fsSL --proto '=https' --tlsv1.2 --max-time 300 -o "$work/TrustedTpm.cab" "$source_url" ||
    die "could not download the TPM vendor CAs from $source_url"
fi
cabextract -q -d "$work/cab" "$work/TrustedTpm.cab" >/dev/null 2>&1 || die "could not extract TrustedTpm.cab"

stage=$work/stage
mkdir -p "$stage"
roots=0
intermediates=0
for vendor in "$work"/cab/*/; do
  vendor=${vendor%/}
  name=${vendor##*/}
  for kind in RootCA IntermediateCA; do
    [[ -d $vendor/$kind ]] || continue
    if [[ $name == Microsoft && $kind == IntermediateCA ]]; then
      continue
    fi
    mkdir -p "$stage/$name/$kind"
    for certificate in "$vendor/$kind"/*; do
      [[ -f $certificate ]] || continue
      cp -- "$certificate" "$stage/$name/$kind/"
      if [[ $kind == RootCA ]]; then
        roots=$((roots + 1))
      else
        intermediates=$((intermediates + 1))
      fi
    done
  done
done
((roots > 0)) || die "TrustedTpm.cab has no vendor root certificates"
chmod -R u=rwX,go=rX "$stage"

# Replace the previous set in one step.
mkdir -p "$(dirname "$directory")"
next=$directory.new
previous=$directory.old
rm -rf -- "$next" "$previous"
cp -a -- "$stage" "$next"
if [[ -d $directory ]]; then
  mv -- "$directory" "$previous"
fi
mv -- "$next" "$directory"
rm -rf -- "$previous"
echo "installed $roots TPM vendor roots and $intermediates intermediates in $directory"
