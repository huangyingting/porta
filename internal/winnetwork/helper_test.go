package winnetwork

import (
	"context"
	"path/filepath"
	"testing"
)

func TestHelperDispatchAndValidationWithoutNetworkEffects(t *testing.T) {
	for _, args := range [][]string{nil, {"-server", "https://example.invalid"}, {"other-command"}} {
		handled, err := RunHelper(context.Background(), args)
		if handled || err != nil {
			t.Fatalf("intercepted normal client arguments %v: %v", args, err)
		}
	}
	for _, args := range [][]string{
		{"network-up"},
		{"network-up", "-unknown"},
		{"network-up", "-state-path", filepath.Join(t.TempDir(), "state.json"), "-server-address", "host.example:443"},
		{"network-up", "-state-path", filepath.Join(t.TempDir(), "state.json"), "-server-address", "192.0.2.1:443", "-address", "invalid"},
		{"network-down", "unexpected-positional"},
	} {
		handled, err := RunHelper(context.Background(), args)
		if !handled || err == nil {
			t.Fatalf("accepted malformed helper arguments %v: %v", args, err)
		}
	}
	handled, err := RunHelper(context.Background(), []string{"network-down", "-state-path", filepath.Join(t.TempDir(), "absent.json")})
	if !handled || err != nil {
		t.Fatalf("idempotent disconnect of absent journal: %v", err)
	}
}
