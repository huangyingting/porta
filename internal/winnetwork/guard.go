package winnetwork

import "context"

type guardEngine interface {
	Replace(context.Context, guardSpec) error
	Remove(context.Context, string) error
	InterfaceLUID(string) (uint64, error)
	InterfaceGUID(uint64) (string, error)
}

// Native DWORD status returns may be sign-extended in a pointer-sized register.
func nativeStatus(result uintptr) uint32 {
	return uint32(result)
}
