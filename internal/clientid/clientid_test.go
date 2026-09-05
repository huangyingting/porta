package clientid

import (
	"errors"
	"regexp"
	"strings"
	"testing"
)

func TestReadableMachineNames(t *testing.T) {
	validID := regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	for _, test := range []struct{ name, want string }{
		{"DESKTOP-123", "DESKTOP-123"},
		{"workstation.example", "workstation.example"},
		{"My Tablet", "My-Tablet"},
		{"  .._John's / Tablet_..  ", "John-s-Tablet"},
		{"Lab_PC-01", "Lab_PC-01"},
		{"123", "123"},
		{"Pad \U0001f4f1", "Pad"},
		{"\u5e73\u677f-01", "01"},
		{"tablet\r\nInjected: header", "tablet-Injected-header"},
		{strings.Repeat("a", 80), strings.Repeat("a", 64)},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := fromName(test.name)
			if err != nil || got != test.want || !validID.MatchString(got) {
				t.Fatalf("fromName(%q) = %q, %v; want %q", test.name, got, err, test.want)
			}
			again, err := fromName(got)
			if err != nil || again != got {
				t.Fatalf("normalization is not stable: %q, %v", again, err)
			}
		})
	}
}

func TestUnavailableMachineNameFailsExplicitly(t *testing.T) {
	for _, name := range []string{"", " \r\n ", ".._--", "\u5e73\u677f", "\x00"} {
		if got, err := fromName(name); got != "" || err == nil {
			t.Fatalf("unusable machine name %q returned %q, %v", name, got, err)
		}
	}
	missing := errors.New("hostname unavailable")
	got, err := fromHostname(func() (string, error) { return "partial-name", missing })
	if got != "" || !errors.Is(err, missing) {
		t.Fatalf("hostname failure was hidden: %q, %v", got, err)
	}
}

func TestRenamingChangesOnlyTheDisplayName(t *testing.T) {
	name := "Office-PC"
	hostname := func() (string, error) { return name, nil }
	for _, current := range []string{"Office-PC", "Office-PC", "Home-PC"} {
		name = current
		got, err := fromHostname(hostname)
		if err != nil || got != current {
			t.Fatalf("machine name not used directly: %q, %v", got, err)
		}
	}
}
