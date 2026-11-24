#!/bin/sh
set -eu

source_certificate=${1:?usage: sync-cert.sh SOURCE_CERTIFICATE SOURCE_KEY DESTINATION_DIRECTORY}
source_key=${2:?usage: sync-cert.sh SOURCE_CERTIFICATE SOURCE_KEY DESTINATION_DIRECTORY}
destination_directory=${3:?usage: sync-cert.sh SOURCE_CERTIFICATE SOURCE_KEY DESTINATION_DIRECTORY}
# Optional group allowed to read the private key, such as the unprivileged
# service user's group.
key_group=${4:-}

if [ -n "$key_group" ]; then
	install -d -m 0750 "$destination_directory"
	chgrp "$key_group" "$destination_directory"
	key_mode=0640
else
	install -d -m 0700 "$destination_directory"
	key_mode=0600
fi
# Applies the key's group and mode, also to an unchanged pair after upgrades.
publish_key_access() {
	if [ -n "$key_group" ]; then
		chgrp "$key_group" "$1"
	fi
	chmod "$key_mode" "$1"
}
exec 9>"$destination_directory/.sync.lock"
flock 9
stage=$(mktemp -d "$destination_directory/.sync.XXXXXX")
publishing=false
committed=false
cleanup() {
	status=$?
	trap - EXIT
	if [ "$publishing" = true ] && [ "$committed" = false ]; then
		for name in server.crt server.key; do
			if [ -f "$stage/$name.old" ]; then
				mv -f "$stage/$name.old" "$destination_directory/$name" || {
					echo "certificate rollback failed; recovery files retained in $stage" >&2
					exit 1
				}
			else
				rm -f "$destination_directory/$name"
			fi
		done
	fi
	rm -rf "$stage"
	exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
install -m 0644 "$source_certificate" "$stage/server.crt"
install -m 0600 "$source_key" "$stage/server.key"
publish_key_access "$stage/server.key"

if [ -f "$destination_directory/server.crt" ] &&
	[ -f "$destination_directory/server.key" ] &&
	cmp -s "$stage/server.crt" "$destination_directory/server.crt" &&
	cmp -s "$stage/server.key" "$destination_directory/server.key"; then
	publish_key_access "$destination_directory/server.key"
	exit 0
fi

certificate_key=$(openssl x509 -in "$stage/server.crt" -pubkey -noout)
private_key=$(openssl pkey -in "$stage/server.key" -pubout)
if [ "$certificate_key" != "$private_key" ]; then
	echo "certificate and private key do not match" >&2
	exit 1
fi

for name in server.crt server.key; do
	if [ -f "$destination_directory/$name" ]; then
		cp -p "$destination_directory/$name" "$stage/$name.old"
	fi
done
publishing=true
mv -f "$stage/server.crt" "$destination_directory/server.crt"
mv -f "$stage/server.key" "$destination_directory/server.key"
committed=true
