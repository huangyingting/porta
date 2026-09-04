#!/bin/sh
set -eu

source_certificate=${1:?usage: sync-cert.sh SOURCE_CERTIFICATE SOURCE_KEY DESTINATION_DIRECTORY}
source_key=${2:?usage: sync-cert.sh SOURCE_CERTIFICATE SOURCE_KEY DESTINATION_DIRECTORY}
destination_directory=${3:?usage: sync-cert.sh SOURCE_CERTIFICATE SOURCE_KEY DESTINATION_DIRECTORY}

install -d -m 0700 "$destination_directory"
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

if [ -f "$destination_directory/server.crt" ] &&
	[ -f "$destination_directory/server.key" ] &&
	cmp -s "$stage/server.crt" "$destination_directory/server.crt" &&
	cmp -s "$stage/server.key" "$destination_directory/server.key"; then
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
