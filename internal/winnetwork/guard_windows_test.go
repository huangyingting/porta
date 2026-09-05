//go:build windows && (amd64 || arm64)

package winnetwork

import (
	"encoding/binary"
	"net/netip"
	"runtime"
	"strings"
	"testing"
	"unsafe"
)

func TestNativeWFPLayouts(t *testing.T) {
	for name, pair := range map[string][2]uintptr{
		"filter size":       {unsafe.Sizeof(wfpFilter{}), 200},
		"conditions size":   {unsafe.Sizeof(wfpCondition{}), 40},
		"sublayer size":     {unsafe.Sizeof(wfpSubLayer{}), 72},
		"filter weight":     {unsafe.Offsetof(wfpFilter{}.weight), 96},
		"filter conditions": {unsafe.Offsetof(wfpFilter{}.conditions), 120},
		"filter action":     {unsafe.Offsetof(wfpFilter{}.action), 128},
		"filter context":    {unsafe.Offsetof(wfpFilter{}.context), 152},
		"filter id":         {unsafe.Offsetof(wfpFilter{}.id), 176},
		"display size":      {unsafe.Sizeof(wfpDisplay{}), 16},
		"blob data":         {unsafe.Offsetof(wfpBlob{}.data), 8},
		"blob size":         {unsafe.Sizeof(wfpBlob{}), 16},
		"value union":       {unsafe.Offsetof(wfpValue{}.value), 8},
		"value size":        {unsafe.Sizeof(wfpValue{}), 16},
		"condition value":   {unsafe.Offsetof(wfpCondition{}.value), 24},
		"action size":       {unsafe.Sizeof(wfpAction{}), 20},
		"sublayer weight":   {unsafe.Offsetof(wfpSubLayer{}.weight), 64},
		"IPv4 mask":         {unsafe.Sizeof(v4Mask{}), 8},
		"IPv6 prefix":       {unsafe.Offsetof(v6Mask{}.bits), 16},
		"IPv6 mask":         {unsafe.Sizeof(v6Mask{}), 17},
	} {
		if pair[0] != pair[1] {
			t.Fatalf("%s: got %d, want SDK layout %d", name, pair[0], pair[1])
		}
	}
}

func TestNativeWFPSDKIdentifiers(t *testing.T) {
	// fwpmu.h, https://github.com/microsoft/win32metadata/tree/main/generation/WinSDK/RecompiledIdlHeaders
	layers := map[string]string{
		"packet4":    "1e5c9fae-8a84-4135-a331-950b54229ecd", // OUTBOUND_IPPACKET_V4
		"packet6":    "a3b3ab6b-3564-488c-9117-f34e82142763", // OUTBOUND_IPPACKET_V6
		"transport4": "09e61aea-d214-46e2-9b21-b26b0b2f28c8", // OUTBOUND_TRANSPORT_V4
		"transport6": "e1735bde-013f-4655-b351-a49e15762df0", // OUTBOUND_TRANSPORT_V6
		"connect4":   "c38d57d1-05a7-4c33-904f-7fbceee60e82", // ALE_AUTH_CONNECT_V4
		"connect6":   "4a72393b-319f-44bc-84c3-ba54dcb3b6b4", // ALE_AUTH_CONNECT_V6
		"accept4":    "e1cd9fe7-f4b5-4273-96c0-592e487b8650", // ALE_AUTH_RECV_ACCEPT_V4
		"accept6":    "a3b42c97-9f04-4672-b87e-cee9c483257f", // ALE_AUTH_RECV_ACCEPT_V6
		"forward4":   "a82acc24-4ee1-4ee1-b465-fd1d25cb10a4", // IPFORWARD_V4
		"forward6":   "7b964818-19c7-493a-b71f-832c3684d28c", // IPFORWARD_V6
	}
	fields := map[string]string{
		"interface":   "4cd62a49-59c3-4969-b7f3-bda5d32890a4", // IP_LOCAL_INTERFACE, not INTERFACE_INDEX
		"application": "d78e1e87-8644-4ea5-9437-d809ecefc971", // ALE_APP_ID
		"address":     "b235ae9a-1d64-49b8-a44c-5ff3d9095045", // IP_REMOTE_ADDRESS
		"port":        "c35a604d-d22b-4e1a-91b4-68f674ee674b", // IP_REMOTE_PORT = ICMP_CODE
		"local-port":  "0c1ba1af-5765-453f-af22-a8f791ac775b", // IP_LOCAL_PORT = ICMP_TYPE
		"protocol":    "3971ef2b-623e-4f9a-8cb1-6e79b806b9a7", // IP_PROTOCOL
		"loopback":    "632ce23b-5167-435c-86d7-e903684aa80c", // FLAGS
	}
	for name, want := range layers {
		if got := layerKeys[name]; got != want {
			t.Errorf("SDK layer %s: %s, want %s", name, got, want)
		}
	}
	for name, want := range fields {
		if got := conditionKeys[name]; got != want {
			t.Errorf("SDK condition %s: %s, want %s", name, got, want)
		}
	}
	for _, ip := range []string{"192.0.2.1", "2001:db8::1"} {
		for _, rule := range guardFilters(testSpec(ip)) {
			if _, exists := layers[rule.layer]; !exists {
				t.Fatalf("unknown layer %s", rule.layer)
			}
			for _, c := range rule.conditions {
				if _, exists := fields[c.field]; !exists {
					t.Fatalf("unknown condition %s", c.field)
				}
				// https://learn.microsoft.com/windows/win32/fwp/filtering-conditions-available-at-each-filtering-layer
				if strings.HasPrefix(rule.layer, "packet") && c.field != "interface" && c.field != "loopback" && c.field != "address" {
					t.Fatalf("unsupported packet condition %s", c.field)
				}
				if c.field == "application" && !strings.HasPrefix(rule.layer, "connect") && !strings.HasPrefix(rule.layer, "accept") {
					t.Fatalf("application identity is unavailable at %s", rule.layer)
				}
			}
		}
	}
}

// Read a pointer arm through its storage, not a uintptr-to-pointer conversion.
// This also permits checkptr-enabled tests to inspect pinned Go allocations.
func nativeValuePointer[T any](value wfpValue) *T {
	return *(**T)(unsafe.Pointer(&value.value))
}

func TestNativeWFPConditionEncoding(t *testing.T) {
	blob := &wfpBlob{}
	var pinned runtime.Pinner
	defer pinned.Unpin()
	pinned.Pin(blob) // Real application IDs are native allocations, not Go blobs.
	input := []condition{
		{"loopback", true},
		{"interface", uint64(0x1234567800000077)},
		{"application", `C:\Porta\porta.exe`},
		{"protocol", uint8(58)},
		{"port", uint16(0x1234)},
		{"local-port", uint16(135)},
		{"address", netip.MustParsePrefix("192.0.2.0/24")},
		{"address", netip.MustParsePrefix("192.0.2.1/32")},
		{"address", netip.MustParsePrefix("0.0.0.0/0")},
		{"address", netip.MustParsePrefix("fe80::/10")},
		{"address", netip.MustParsePrefix("2001:db8::1/128")},
	}
	conditions := nativeConditions(input, blob, &pinned)
	runtime.GC()
	// No typed references to the masks/LUID remain except in the Pinner.
	runtime.GC()
	for i, c := range conditions {
		if c.key != guid(conditionKeys[input[i].field]) {
			t.Fatalf("condition %d has wrong key", i)
		}
		if i != 0 && c.match != 0 {
			t.Fatalf("condition %d must use FWP_MATCH_EQUAL", i)
		}
	}
	if c := conditions[0]; c.match != 6 || c.value.kind != 3 || c.value.value != 1 {
		t.Fatalf("loopback needs FLAGS_ALL_SET, UINT32, IS_LOOPBACK: %+v", c)
	}
	if c := conditions[1]; c.value.kind != 4 || *nativeValuePointer[uint64](c.value) != input[1].value {
		t.Fatalf("LUID must be a pointer to a full UINT64: %+v", c)
	}
	if c := conditions[2]; c.value.kind != 12 || nativeValuePointer[wfpBlob](c.value) != blob {
		t.Fatalf("application ID must use BYTE_BLOB_TYPE: %+v", c)
	}
	if c := conditions[3]; c.value.kind != 1 || c.value.value != 58 {
		t.Fatalf("protocol must use UINT8: %+v", c)
	}
	for _, i := range []int{4, 5} {
		if c := conditions[i]; c.value.kind != 2 || c.value.value != uintptr(input[i].value.(uint16)) {
			t.Fatalf("port/ICMP must be UINT16 in host order: %+v", c)
		}
	}
	for i := 6; i < len(input); i++ {
		prefix := input[i].value.(netip.Prefix)
		c := conditions[i]
		if prefix.Addr().Is4() {
			want := prefix.Addr().As4()
			mask := nativeValuePointer[v4Mask](c.value)
			if c.value.kind != 0x100 || mask.address != binary.BigEndian.Uint32(want[:]) || mask.mask != ^uint32(0)<<(32-prefix.Bits()) {
				t.Fatalf("wrong IPv4 mask for %s: %+v", prefix, mask)
			}
		} else {
			mask := nativeValuePointer[v6Mask](c.value)
			if c.value.kind != 0x101 || mask.address != prefix.Addr().As16() || int(mask.bits) != prefix.Bits() {
				t.Fatalf("wrong IPv6 mask for %s: %+v", prefix, mask)
			}
		}
	}
}
