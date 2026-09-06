#!/bin/sh
set -eu

cycles=${1:-10}
offline_seconds=${OFFLINE_SECONDS:-5}
recovery_seconds=${RECOVERY_SECONDS:-20}

case "$cycles" in
	""|*[!0-9]*)
		echo "cycles must be a positive integer" >&2
		exit 2
		;;
esac
if ! [ "$cycles" -gt 0 ] 2>/dev/null; then
	echo "cycles must be a positive integer" >&2
	exit 2
fi

command -v adb >/dev/null 2>&1 || {
	echo "adb is required" >&2
	exit 1
}
adb get-state >/dev/null

porta_vpn_is_active() {
	adb shell dumpsys connectivity |
		grep -E 'TRANSPORT_VPN|type: VPN' >/dev/null &&
		adb shell dumpsys activity services dev.porta.android/.TunnelService |
		grep -q 'ServiceRecord'
}

if ! porta_vpn_is_active; then
	echo "connect Porta on the attached device before starting the soak test" >&2
	exit 1
fi

wifi_disabled=false
restore_wifi() {
	status=$?
	trap - EXIT
	if [ "$wifi_disabled" = true ]; then
		adb shell svc wifi enable || status=1
	fi
	exit "$status"
}
trap restore_wifi EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

cycle=1
while [ "$cycle" -le "$cycles" ]; do
	echo "cycle $cycle/$cycles: disabling Wi-Fi"
	wifi_disabled=true
	adb shell svc wifi disable
	sleep "$offline_seconds"
	echo "cycle $cycle/$cycles: enabling Wi-Fi"
	adb shell svc wifi enable
	wifi_disabled=false
	sleep "$recovery_seconds"
	if ! porta_vpn_is_active; then
		echo "Porta VPN was not active after reconnect cycle $cycle" >&2
		exit 1
	fi
	cycle=$((cycle + 1))
done

echo "completed $cycles reconnect cycles"
