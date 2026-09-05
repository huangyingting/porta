package main

import (
	"flag"
	"io"
	"os"
	"testing"
)

func TestServerMTUDefaultsAndOverrides(t *testing.T) {
	originalArgs, originalFlags := os.Args, flag.CommandLine
	t.Cleanup(func() { os.Args, flag.CommandLine = originalArgs, originalFlags })
	// Stop run immediately after parsing, before opening files or networking.
	t.Setenv("PORTA_TOKEN", "short")
	for _, test := range []struct {
		name string
		args []string
		mtu  string
		auto string
	}{
		{"default", nil, "1400", "true"},
		{"custom-ceiling", []string{"--mtu", "1280"}, "1280", "true"},
		{"fixed-fallback", []string{"--auto-mtu=false", "--mtu", "1100"}, "1100", "false"},
		{"fixed-larger", []string{"--auto-mtu=false", "--mtu", "1300"}, "1300", "false"},
	} {
		t.Run(test.name, func(t *testing.T) {
			flag.CommandLine = flag.NewFlagSet("porta-server", flag.ContinueOnError)
			flag.CommandLine.SetOutput(io.Discard)
			os.Args = append([]string{"porta-server"}, test.args...)
			if err := run(); err == nil || err.Error() != "PORTA_TOKEN must contain at least 16 characters" {
				t.Fatalf("server did not stop at the pre-networking validation guard: %v", err)
			}
			for name, want := range map[string]string{"mtu": test.mtu, "auto-mtu": test.auto} {
				got := flag.CommandLine.Lookup(name)
				if got == nil || got.Value.String() != want {
					t.Fatalf("flag %s = %v, want %s", name, got, want)
				}
			}
		})
	}
}
