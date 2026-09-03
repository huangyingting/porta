#!/bin/sh
set -eu

source_certificate=${1:?usage: sync-cert.sh SOURCE_CERTIFICATE SOURCE_KEY DESTINATION_DIRECTORY}
source_key=${2:?usage: sync-cert.sh SOURCE_CERTIFICATE SOURCE_KEY DESTINATION_DIRECTORY}
destination_directory=${3:?usage: sync-cert.sh SOURCE_CERTIFICATE SOURCE_KEY DESTINATION_DIRECTORY}

install -d -m 0700 "$destination_directory"
install -m 0644 "$source_certificate" "$destination_directory/server.crt.new"
install -m 0600 "$source_key" "$destination_directory/server.key.new"

if [ -f "$destination_directory/server.crt" ] &&
	[ -f "$destination_directory/server.key" ] &&
	cmp -s "$destination_directory/server.crt.new" "$destination_directory/server.crt" &&
	cmp -s "$destination_directory/server.key.new" "$destination_directory/server.key"; then
	rm -f "$destination_directory/server.crt.new" "$destination_directory/server.key.new"
	exit 0
fi

certificate_key=$(openssl x509 -in "$destination_directory/server.crt.new" -pubkey -noout)
private_key=$(openssl pkey -in "$destination_directory/server.key.new" -pubout)
if [ "$certificate_key" != "$private_key" ]; then
	echo "certificate and private key do not match" >&2
	exit 1
fi

mv -f "$destination_directory/server.crt.new" "$destination_directory/server.crt"
mv -f "$destination_directory/server.key.new" "$destination_directory/server.key"
