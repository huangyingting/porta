package winnetwork

import "testing"

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
