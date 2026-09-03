#!/bin/sh
set -eu

cycles=${1:-10}
offline_seconds=${OFFLINE_SECONDS:-5}
recovery_seconds=${RECOVERY_SECONDS:-20}

command -v adb >/dev/null 2>&1 || {
	echo "adb is required" >&2
	exit 1
}
adb get-state >/dev/null

vpn_is_active() {
	adb shell dumpsys connectivity |
		grep -E 'TRANSPORT_VPN|type: VPN' >/dev/null
}

if ! vpn_is_active; then
	echo "connect hTun on the attached device before starting the soak test" >&2
	exit 1
fi

cycle=1
while [ "$cycle" -le "$cycles" ]; do
	echo "cycle $cycle/$cycles: disabling Wi-Fi"
	adb shell svc wifi disable
	sleep "$offline_seconds"
	echo "cycle $cycle/$cycles: enabling Wi-Fi"
	adb shell svc wifi enable
	sleep "$recovery_seconds"
	if ! vpn_is_active; then
		echo "VPN was not active after reconnect cycle $cycle" >&2
		exit 1
	fi
	cycle=$((cycle + 1))
done

echo "completed $cycles reconnect cycles"
