package main

import (
	"testing"
	"time"

	"github.com/huangyingting/porta/internal/clientapp"
	"github.com/huangyingting/porta/internal/tunnel"
)

func TestProgressPublishesChangedEffectiveMTU(t *testing.T) {
	controller, _, _ := newTestDesktopController(t)
	at := time.Now()
	controller.connected, controller.running = true, true
	controller.connectedAt = at
	controller.mtu = 1280
	controller.transport = "h3"
	controller.handleConnectionEvent(clientapp.Event{
		State: clientapp.StateConnected, Message: "Connected", ConnectedAt: at,
		Lease: tunnel.Lease{MTU: 1100}, Transport: tunnel.TransportHTTP3,
	})
	snapshot := controller.Snapshot()
	if snapshot.MTU != 1100 || snapshot.Detail != "HTTP/3 MASQUE - fast and resilient - MTU 1100" {
		t.Fatalf("effective MTU update was swallowed as traffic-only progress: %+v", snapshot)
	}
	if len(snapshot.Activity) != 0 {
		t.Fatal("MTU metadata refresh added redundant connection activity")
	}
}
