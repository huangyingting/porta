#!/usr/bin/env bash
set -euo pipefail

version_file=internal/buildinfo/VERSION
version=$(<"$version_file")
if [[ ! $version =~ ^0\.1\.([0-9]{1,3})$ ]]; then
  echo "$version_file must contain 0.1.PATCH with PATCH between 0 and 999" >&2
  exit 1
fi
patch=$((10#${BASH_REMATCH[1]}))

previous_revision=${1:-}
if [[ -z $previous_revision || $previous_revision =~ ^0+$ ]]; then
  exit 0
fi
previous=$(git show "$previous_revision:$version_file" 2>/dev/null || true)
if [[ -z $previous ]]; then
  exit 0
fi
if [[ ! $previous =~ ^0\.1\.([0-9]{1,3})$ ]]; then
  echo "previous $version_file contains an invalid version: $previous" >&2
  exit 1
fi
previous_patch=$((10#${BASH_REMATCH[1]}))
if ((patch != previous_patch + 1)); then
  echo "application version must increment exactly one patch: $previous -> $version" >&2
  exit 1
fi
