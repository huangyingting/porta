package buildinfo

import (
	"regexp"
	"testing"
)

func TestVersion(t *testing.T) {
	if !regexp.MustCompile(`^0\.1\.[0-9]{1,3}$`).MatchString(Version) {
		t.Fatalf("Version = %q, want 0.1.PATCH", Version)
	}
}

func TestIsVersionRequest(t *testing.T) {
	if !IsVersionRequest([]string{"--version"}) || !IsVersionRequest([]string{"-version"}) {
		t.Fatal("version request was not recognized")
	}
	if IsVersionRequest(nil) || IsVersionRequest([]string{"--version", "extra"}) {
		t.Fatal("invalid version request was accepted")
	}
}
