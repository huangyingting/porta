package winnetwork

import "testing"

func nativeGuardFilterFlagsMatch(flags uint32) bool {
	// BFE may add INDEXED (0x40), a lookup optimization, to PERSISTENT (0x01).
	// All other flags, including DISABLED and CLEAR_ACTION_RIGHT, remain forbidden.
	// https://learn.microsoft.com/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter0
	return flags&^0x40 == 0x01
}

func TestNativeGuardFilterFlags(t *testing.T) {
	for _, test := range []struct {
		name  string
		flags uint32
		want  bool
	}{
		{"persistent", 0x01, true},
		{"persistent indexed", 0x41, true},
		{"not persistent", 0, false},
		{"indexed but not persistent", 0x40, false},
		{"boot time", 0x03, false},
		{"provider context", 0x05, false},
		{"hard permit", 0x09, false},
		{"indexed hard permit", 0x49, false},
		{"unregistered callout permit", 0x11, false},
		{"disabled", 0x21, false},
		{"indexed disabled", 0x61, false},
		{"unknown flag", 0x80000041, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := nativeGuardFilterFlagsMatch(test.flags); got != test.want {
				t.Fatalf("nativeGuardFilterFlagsMatch(%#x) = %t, want %t", test.flags, got, test.want)
			}
		})
	}
}

func TestNativeStatusUsesDWORDWidth(t *testing.T) {
	for _, test := range []struct {
		name   string
		result uint64
		want   uint32
	}{
		{"success", 0, 0},
		{"success with upper bits", 0xffffffff00000000, 0},
		{"win32 error", 5, 5},
		{"filter not found", 0x80320003, 0x80320003},
		{"sign extended filter not found", 0xffffffff80320003, 0x80320003},
		{"sublayer not found", 0x80320007, 0x80320007},
		{"sign extended sublayer not found", 0xffffffff80320007, 0x80320007},
		{"already exists", 0x80320009, 0x80320009},
		{"sign extended already exists", 0xffffffff80320009, 0x80320009},
		{"unexpected error", 0xffffffff80320004, 0x80320004},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := nativeStatus(uintptr(test.result)); got != test.want {
				t.Fatalf("nativeStatus(%#x) = %#x, want %#x", test.result, got, test.want)
			}
		})
	}
}
