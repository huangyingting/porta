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
baseline_patch=$previous_patch
head_commit=$(git rev-parse --verify HEAD)
release_tags=$(git tag --list 'v0.1.*')
while IFS= read -r tag; do
  [[ $tag =~ ^v0\.1\.(0|[1-9][0-9]{0,2})$ ]] || continue
  tag_patch=$((10#${BASH_REMATCH[1]}))
  ((tag_patch > baseline_patch)) || continue
  tag_commit=$(git rev-parse --verify "refs/tags/$tag^{commit}")
  if [[ "$tag_commit" == "$head_commit" && "$tag_patch" == "$patch" ]]; then
    continue
  fi
  baseline_patch=$tag_patch
done <<< "$release_tags"
if ((patch != baseline_patch + 1)); then
  echo "application version must be the next patch above the base and release tags: 0.1.$baseline_patch -> $version" >&2
  exit 1
fi
