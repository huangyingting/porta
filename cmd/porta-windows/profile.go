//go:build windows

package main

import (
	"time"

	"github.com/huangyingting/porta/internal/clientprofile"
	"github.com/huangyingting/porta/internal/tunnel"
)

func transportIndex(transport tunnel.Transport) int {
	switch transport {
	case tunnel.TransportHTTP3:
		return 1
	case tunnel.TransportHTTP2:
		return 2
	default:
		return 0
	}
}

func selectedTransport(index int) tunnel.Transport {
	switch index {
	case 1:
		return tunnel.TransportHTTP3
	case 2:
		return tunnel.TransportHTTP2
	default:
		return tunnel.TransportAuto
	}
}

func profileWithFields(original, fields clientprofile.Profile) clientprofile.Profile {
	if original.ID == "" {
		original.Reconnect = true
		original.ReconnectMaxDelay = 30 * time.Second
	}
	original.ID = fields.ID
	original.Name = fields.Name
	original.ServerURL = fields.ServerURL
	original.ClientID = fields.ClientID
	original.Transport = fields.Transport
	return original
}
