package clientid

import "testing"

func TestFromHostname(t *testing.T) {
	tests := []struct {
		name     string
		hostname string
		fallback string
		want     string
	}{
		{name: "valid", hostname: "workstation-1", fallback: "porta-client", want: "workstation-1"},
		{name: "sanitize", hostname: " office laptop ", fallback: "porta-client", want: "office-laptop"},
		{name: "empty", hostname: "...", fallback: "porta-client", want: "porta-client"},
		{name: "truncate", hostname: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-extra", fallback: "porta-client", want: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-e"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := FromHostname(test.hostname, test.fallback); got != test.want {
				t.Fatalf("FromHostname(%q) = %q, want %q", test.hostname, got, test.want)
			}
		})
	}
}
