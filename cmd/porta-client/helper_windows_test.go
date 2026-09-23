package main

import "testing"

func TestWintunBoundaryCannotBeBypassedWithFlagLikeValues(t *testing.T) {
	for _, test := range []struct {
		args []string
		want bool
	}{
		{nil, true},
		{[]string{"--manual-network"}, true},
		{[]string{"--cleanup-network"}, false},
		{[]string{"--cleanup-network=false"}, true},
		{[]string{"--cleanup-network", "--cleanup-network=false"}, true},
		{[]string{"--cleanup-network", "--identity", `C:\unused-during-cleanup`}, false},
		{[]string{"--identity", "--cleanup-network"}, true},
		{[]string{"--token", "--cleanup-network"}, true},
		{[]string{"--server", "--help"}, true},
		{[]string{"--help"}, false},
		{[]string{"--new-option"}, true},
		{[]string{"--cleanup-network", "--new-option"}, true},
	} {
		if got := requiresWintun(test.args); got != test.want {
			t.Errorf("requiresWintun(%q) = %v, want %v", test.args, got, test.want)
		}
	}
}
