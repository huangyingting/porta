//go:build !windows

package winnetwork

import "errors"

func nativeInterfaceMTU(uint64) (uint32, error) {
	return 0, errors.New("Windows IP Helper API is unavailable")
}

func setNativeInterfaceMTU(uint64, uint32) error {
	return errors.New("Windows IP Helper API is unavailable")
}
