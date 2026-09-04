#!/usr/bin/env bash
set -euo pipefail

version_file=internal/buildinfo/VERSION
version=$(<"$version_file")
if [[ ! $version =~ ^0\.1\.(0|[1-9][0-9]{0,2})$ ]]; then
  echo "$version_file must contain 0.1.PATCH with PATCH between 0 and 999" >&2
  exit 1
fi
patch=$((10#${BASH_REMATCH[1]}))

previous_revision=${1:-}
if [[ -z $previous_revision || $previous_revision =~ ^0+$ ]]; then
  exit 0
fi
previous_commit=$(git rev-parse --verify --end-of-options "$previous_revision^{commit}" 2>/dev/null) || {
  echo "cannot resolve previous revision: $previous_revision" >&2
  exit 1
}
if ! git cat-file -e "$previous_commit:$version_file" 2>/dev/null; then
  exit 0
fi
previous=$(git show "$previous_commit:$version_file")
if [[ ! $previous =~ ^0\.1\.(0|[1-9][0-9]{0,2})$ ]]; then
  echo "previous $version_file contains an invalid version: $previous" >&2
  exit 1
fi
previous_patch=$((10#${BASH_REMATCH[1]}))
if ((patch != previous_patch + 1)); then
  echo "application version must increment exactly one patch: $previous -> $version" >&2
  exit 1
fi
