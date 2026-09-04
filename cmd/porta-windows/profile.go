//go:build windows

package main

import (
	"time"

	"github.com/huangyingting/porta/internal/clientprofile"
)

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
