package clientid

import (
	"encoding/base64"
	"encoding/hex"
	"regexp"
	"strings"
	"testing"
)

func TestOSDerivedIdentityIsStableAndPrivate(t *testing.T) {
	const machineID = "00112233445566778899aabbccddeeff"
	for _, platform := range []string{"linux", "windows"} {
		t.Run(platform, func(t *testing.T) {
			value := machineID
			if platform == "windows" {
				value = "00112233-4455-6677-8899-aabbccddeeff"
			}
			first, err := derive(platform, value)
			if err != nil {
				t.Fatal(err)
			}
			second, err := derive(platform, " \n"+strings.ToUpper(value)+"\r\n")
			if err != nil || first != second {
				t.Fatalf("OS identity changed with equivalent formatting: %v", err)
			}
			if !regexp.MustCompile(`^`+platform[:1]+`-[A-Za-z0-9_-]{22}$`).MatchString(first) || len(first) != 24 {
				t.Fatalf("invalid device ID format: %q", first)
			}
			if strings.Contains(first, machineID) || strings.Contains(first, value) {
				t.Fatal("device ID exposes the system-wide identity")
			}
			other, err := derive(platform, strings.ReplaceAll(value, "00112233", "11223344"))
			if err != nil || first == other {
				t.Fatalf("different OS identities were not distinguished: %v", err)
			}
		})
	}
	linux, _ := derive("linux", machineID)
	windows, _ := derive("windows", "00112233-4455-6677-8899-aabbccddeeff")
	if strings.TrimPrefix(linux, "l-") == strings.TrimPrefix(windows, "w-") {
		t.Fatal("identity derivation is not platform scoped")
	}
}

func TestInvalidOSIdentityHasNoFallback(t *testing.T) {
	for _, test := range []struct{ platform, value string }{
		{"linux", ""}, {"linux", "uninitialized"}, {"linux", "laptop"},
		{"linux", strings.Repeat("0", 32)}, {"linux", strings.Repeat("1", 31)},
		{"linux", strings.Repeat("1", 33)}, {"linux", strings.Repeat("g", 32)},
		{"linux", "00112233-4455-6677-8899-aabbccddeeff"},
		{"windows", ""}, {"windows", "00112233445566778899aabbccddeeff"},
		{"windows", "00000000-0000-0000-0000-000000000000"},
		{"windows", "00112233-4455-6677-8899-aabbccddeefg"},
		{"windows", "0011223-34455-6677-8899-aabbccddeeff"},
		{"other", "00112233445566778899aabbccddeeff"},
	} {
		if id, err := derive(test.platform, test.value); err == nil || id != "" {
			t.Fatalf("invalid %s identity produced a fallback: %q, %v", test.platform, id, err)
		}
	}
}

func TestDerivationDoesNotChangeAcrossReleases(t *testing.T) {
	for _, test := range []struct{ platform, value, want, digest string }{
		{"linux", "00112233445566778899aabbccddeeff", "l-zDTW4gZ4UzLuzoCrppILZg", "cc34d6e206785332eece80aba6920b66"},
		{"windows", "00112233-4455-6677-8899-aabbccddeeff", "w-_F9iEn_PCIp5yd5n3sB3Cw", "fc5f62127fcf088a79c9de67dec0770b"},
	} {
		got, err := derive(test.platform, test.value)
		if err != nil || got != test.want {
			t.Fatalf("persistent %s device identity changed: %q, %v", test.platform, got, err)
		}
		decoded, err := base64.RawURLEncoding.DecodeString(got[2:])
		if err != nil || hex.EncodeToString(decoded) != test.digest {
			t.Fatal("compact encoding discarded or changed identity bits")
		}
	}
}
