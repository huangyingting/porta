//go:build windows

package winnetwork

import (
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

var setIPInterfaceEntry = windows.NewLazySystemDLL("iphlpapi.dll").NewProc("SetIpInterfaceEntry")

func nativeInterfaceMTU(luid uint64) (uint32, error) {
	row := windows.MibIpInterfaceRow{
		Family:        windows.AF_INET,
		InterfaceLuid: luid,
	}
	if err := windows.GetIpInterfaceEntry(&row); err != nil {
		return 0, fmt.Errorf("GetIpInterfaceEntry: %w", err)
	}
	return row.NlMtu, nil
}

func setNativeInterfaceMTU(luid uint64, mtu uint32) error {
	row := windows.MibIpInterfaceRow{
		Family:        windows.AF_INET,
		InterfaceLuid: luid,
	}
	if err := windows.GetIpInterfaceEntry(&row); err != nil {
		return fmt.Errorf("GetIpInterfaceEntry before update: %w", err)
	}
	row.NlMtu = mtu
	// Windows requires SitePrefixLength to be zero when updating IPv4 rows.
	row.SitePrefixLength = 0
	result, _, _ := setIPInterfaceEntry.Call(uintptr(unsafe.Pointer(&row)))
	runtime.KeepAlive(&row)
	if code := nativeStatus(result); code != 0 {
		return fmt.Errorf("SetIpInterfaceEntry: %w", windows.Errno(code))
	}
	return nil
}
