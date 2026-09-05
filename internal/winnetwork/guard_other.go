//go:build !windows || (!amd64 && !arm64)

package winnetwork

import (
	"context"
	"errors"
)

type nativeGuard struct{}

func (nativeGuard) Replace(context.Context, guardSpec) error {
	return errors.New("persistent WFP leak protection requires 64-bit Windows")
}

func (nativeGuard) Remove(context.Context, string) error {
	return errors.New("persistent WFP leak protection requires 64-bit Windows")
}

func (nativeGuard) InterfaceLUID(string) (uint64, error) {
	return 0, errors.New("persistent WFP leak protection requires 64-bit Windows")
}

func (nativeGuard) InterfaceGUID(uint64) (string, error) {
	return "", errors.New("persistent WFP leak protection requires 64-bit Windows")
}
