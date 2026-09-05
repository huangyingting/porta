package winnetwork

import "context"

type guardEngine interface {
	Replace(context.Context, guardSpec) error
	Remove(context.Context, string) error
	InterfaceLUID(string) (uint64, error)
	InterfaceGUID(uint64) (string, error)
}
