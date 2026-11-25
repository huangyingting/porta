#!/usr/bin/env bash
# Archives the Porta iOS and macOS apps and uploads them to App Store
# Connect, for TestFlight and App Store review. Signing is automatic: Xcode
# creates or reuses the certificates and profiles with the API key.
#
# Needs macOS with Xcode, apple/build/Porta.xcframework (make build-apple),
# apple/App/Porta.xcodeproj (make apple-project), and an App Store Connect
# API key with the Admin role, in the environment:
#   APPLE_TEAM_ID   the 10-character team ID
#   ASC_KEY_ID      the key ID
#   ASC_ISSUER_ID   the issuer ID
#   ASC_KEY_P8      the contents of the AuthKey_*.p8 file
#
# Usage: scripts/upload-apple.sh BUILD_NUMBER [iOS] [macOS]
set -euo pipefail

[[ $(uname -s) == Darwin ]] || { echo "upload-apple.sh needs macOS with Xcode" >&2; exit 2; }
build_number=${1:?usage: upload-apple.sh BUILD_NUMBER [iOS] [macOS]}
shift
platforms=("$@")
[[ ${#platforms[@]} -gt 0 ]] || platforms=(iOS macOS)
[[ $build_number =~ ^[1-9][0-9]*$ ]] || { echo "build number must be a positive integer" >&2; exit 2; }
for name in APPLE_TEAM_ID ASC_KEY_ID ASC_ISSUER_ID ASC_KEY_P8; do
  [[ -n ${!name:-} ]] || { echo "$name is not set; see apple/README.md" >&2; exit 2; }
done
[[ $APPLE_TEAM_ID =~ ^[A-Z0-9]{10}$ ]] || { echo "APPLE_TEAM_ID must be 10 letters and digits" >&2; exit 2; }

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
project=$repository_root/apple/App/Porta.xcodeproj
[[ -d $project ]] || { echo "run make apple-project first" >&2; exit 2; }
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
key=$work/AuthKey.p8
(umask 077 && printf '%s\n' "$ASC_KEY_P8" >"$key")
authentication=(
  -allowProvisioningUpdates
  -authenticationKeyPath "$key"
  -authenticationKeyID "$ASC_KEY_ID"
  -authenticationKeyIssuerID "$ASC_ISSUER_ID"
)
cat >"$work/ExportOptions.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>method</key><string>app-store-connect</string>
  <key>destination</key><string>upload</string>
  <key>teamID</key><string>$APPLE_TEAM_ID</string>
  <key>signingStyle</key><string>automatic</string>
  <key>manageAppVersionAndBuildNumber</key><false/>
</dict>
</plist>
PLIST

for platform in "${platforms[@]}"; do
  case $platform in
    iOS|macOS) ;;
    *) echo "unknown platform $platform" >&2; exit 2 ;;
  esac
  archive=$work/Porta-$platform.xcarchive
  echo "archiving Porta for $platform, build $build_number"
  xcodebuild archive -quiet -project "$project" -scheme "Porta-$platform" \
    -destination "generic/platform=$platform" -archivePath "$archive" \
    DEVELOPMENT_TEAM="$APPLE_TEAM_ID" CURRENT_PROJECT_VERSION="$build_number" \
    "${authentication[@]}"
  echo "uploading Porta for $platform"
  xcodebuild -exportArchive -archivePath "$archive" \
    -exportOptionsPlist "$work/ExportOptions.plist" -exportPath "$work/export-$platform" \
    "${authentication[@]}"
done
echo "uploaded; the builds appear in App Store Connect under TestFlight once processed"
