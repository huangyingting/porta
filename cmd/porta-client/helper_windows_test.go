package main

import (
	"context"
	"testing"
)

func TestNetworkHelperDefersClientArgumentsToMainParser(t *testing.T) {
	for _, args := range [][]string{
		nil,
		{"--manual-network"},
		{"--cleanup-network"},
		{"--cleanup-network=false"},
		{"--cleanup-network", "--cleanup-network=false"},
		{"--cleanup-network", "--identity", `C:\unused-during-cleanup`},
		{"--identity", "--cleanup-network"},
		{"--token", "--cleanup-network"},
		{"--server", "--help"},
		{"--help"},
		{"--new-option"},
		{"--cleanup-network", "--new-option"},
	} {
		if handled, err := runNetworkHelper(context.Background(), args); handled || err != nil {
			t.Errorf("client arguments %q triggered a helper or DLL load: handled=%t err=%v", args, handled, err)
		}
	}
}
