//go:build !windows

package device

import "golang.zx2c4.com/wireguard/tun"

func createNativeTUN(name string, mtu int) (tun.Device, error) {
	return tun.CreateTUN(name, mtu)
}
