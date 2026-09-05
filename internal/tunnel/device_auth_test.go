package tunnel_test

import (
	"time"

	"github.com/huangyingting/porta/internal/deviceauth"
	"github.com/huangyingting/porta/internal/tunnel"
)

func withTestDeviceProof(config tunnel.Config) tunnel.Config {
	if config.DeviceProof == nil {
		key, err := deviceauth.GenerateKey()
		if err != nil {
			panic(err)
		}
		config.DeviceProof = func(method, path string) (deviceauth.Proof, error) {
			return deviceauth.NewProof(key, "test-device", config.Token, method, path, time.Now(), nil)
		}
	}
	return config
}
