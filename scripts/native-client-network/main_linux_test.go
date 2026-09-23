//go:build linux && !android

package main

import (
	"strings"
	"testing"
)

func TestNativeClientNetworkRequiresOptIn(t *testing.T) {
	t.Setenv("PORTA_NATIVE_CLIENT_NETWORK_TEST", "")
	if err := run("unused"); err == nil || !strings.Contains(err.Error(), "opt-in") {
		t.Fatalf("native network ran without explicit opt-in: %v", err)
	}
}
