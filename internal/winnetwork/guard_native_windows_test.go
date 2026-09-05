//go:build windows && (amd64 || arm64)

package winnetwork

import (
	"crypto/rand"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	nativeFilterGet   = wfp.NewProc("FwpmFilterGetByKey0")
	nativeSubLayerGet = wfp.NewProc("FwpmSubLayerGetByKey0")
	nativeLayerGet    = wfp.NewProc("FwpmLayerGetByKey0")
)

// FWPM_FIELD0 and FWPM_LAYER0 from fwpmtypes.h; used only for read-only
// inspection of the live BFE schema.
type nativeField struct {
	key            *windows.GUID
	kind, dataType uint32
}

type nativeLayer struct {
	key             windows.GUID
	display         wfpDisplay
	flags, count    uint32
	fields          *nativeField
	defaultSublayer windows.GUID
	id              uint16
}

var (
	_ [16]byte = [unsafe.Sizeof(nativeField{})]byte{}
	_ [72]byte = [unsafe.Sizeof(nativeLayer{})]byte{}
	_ [40]byte = [unsafe.Offsetof(nativeLayer{}.fields)]byte{}
	_ [64]byte = [unsafe.Offsetof(nativeLayer{}.id)]byte{}
)

// Elevated Windows acceptance, explicitly enabled with:
//
//	$env:PORTA_WFP_NATIVE_TEST='1'
//	go test ./internal/winnetwork -run '^TestNativeWFPTransactionRollback$' -count=1 -v
//
// No transaction is EVER committed here. Filters are invisible to packet
// classification until commit. Abort runs even after Fatal/panic; closing the
// engine (or process termination) also aborts an outstanding transaction.
// https://learn.microsoft.com/windows/win32/fwp/object-management
func TestNativeWFPTransactionRollback(t *testing.T) {
	if value := os.Getenv("PORTA_WFP_NATIVE_TEST"); value != "1" {
		if value != "" {
			t.Fatal("PORTA_WFP_NATIVE_TEST must be 1 or unset")
		}
		t.Skip("set PORTA_WFP_NATIVE_TEST=1 on elevated Windows to require live BFE acceptance")
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Fatal("native WFP acceptance requires an elevated administrator token")
	}
	app, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	luid := nativeTestInterfaceLUID(t)
	for _, ip := range []string{"192.0.2.1", "2001:db8::1"} {
		for _, tunLUID := range []uint64{0, luid} {
			t.Run(fmt.Sprintf("%s/tun=%t", ip, tunLUID != 0), func(t *testing.T) {
				var nonce [16]byte
				if _, err := rand.Read(nonce[:]); err != nil {
					t.Fatal(err)
				}
				spec := testSpec(ip)
				spec.Key = fmt.Sprintf("native-abort-%x", nonce)
				spec.Application, spec.InterfaceLUID = app, tunLUID
				nativeGuardRollback(t, spec)
			})
		}
	}
}

func nativeTestInterfaceLUID(t *testing.T) uint64 {
	t.Helper()
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	// Use an existing loopback LUID to exercise the TUN condition's encoding
	// without creating a TUN, changing routes, or permitting any live traffic.
	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback != 0 {
			luid, err := (nativeGuard{}).InterfaceLUID(iface.Name)
			if err != nil {
				t.Fatal(err)
			}
			return luid
		}
	}
	t.Fatal("no loopback interface available for native LUID acceptance")
	return 0
}

func nativeOpenEngine(t *testing.T) uintptr {
	t.Helper()
	var engine uintptr
	if err := wfpCall(engineOpen, 0, 10, 0, 0, uintptr(unsafe.Pointer(&engine))); err != nil {
		t.Fatalf("live BFE is required: %v", err)
	}
	return engine
}

func nativeCloseEngine(t *testing.T, engine uintptr) {
	t.Helper()
	if err := wfpCall(engineClose, engine); err != nil {
		t.Errorf("close BFE engine: %v", err)
	}
}

func nativeGuardRollback(t *testing.T, spec guardSpec) {
	t.Helper()
	engine := nativeOpenEngine(t)
	defer nativeCloseEngine(t, engine)
	nativeAssertGuardAbsent(t, engine, spec.Key)
	nativeAssertLayerSchema(t, engine, guardFilters(spec))
	if err := wfpCall(transactionBegin, engine, 0); err != nil {
		t.Fatal(err)
	}
	// There is deliberately no commit option, success path, or call to Replace.
	defer func() {
		if err := wfpCall(transactionAbort, engine); err != nil {
			t.Errorf("mandatory transaction abort failed: %v", err)
			// Session closure is the fallback abort. Never issue more writes.
			return
		}
		nativeAssertGuardAbsent(t, engine, spec.Key)
		observer := nativeOpenEngine(t)
		defer nativeCloseEngine(t, observer)
		nativeAssertGuardAbsent(t, observer, spec.Key)
	}()
	for pass := 0; pass < 2; pass++ {
		// The second pass exercises ALREADY_EXISTS and exact owned-key
		// replacement, including removal of the old tail of a longer policy.
		current := spec
		if pass == 1 {
			if current.Endpoint.IP.Is6() {
				current.Endpoint.IP = testSpec("192.0.2.1").Endpoint.IP
			} else {
				current.Endpoint.IP = testSpec("2001:db8::1").Endpoint.IP
			}
		}
		if err := installGuard(engine, current); err != nil {
			t.Fatalf("production installation pass %d: %v", pass, err)
		}
		nativeAssertStagedGuard(t, engine, current)
	}
}

func nativeAssertGuardAbsent(t *testing.T, engine uintptr, owner string) {
	t.Helper()
	key := guid(objectKey(owner, -1))
	var sublayer *wfpSubLayer
	result, _, _ := nativeSubLayerGet.Call(engine, uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(&sublayer)))
	code := nativeStatus(result)
	if sublayer != nil {
		freeMemory.Call(uintptr(unsafe.Pointer(&sublayer)))
	}
	if code != 0x80320007 { // FWP_E_SUBLAYER_NOT_FOUND
		t.Fatalf("sublayer exists or absence query failed: %#x", code)
	}
	for index := 0; index < maxGuardFilters; index++ {
		nativeAssertFilterAbsent(t, engine, owner, index)
	}
}

func nativeAssertFilterAbsent(t *testing.T, engine uintptr, owner string, index int) {
	t.Helper()
	key := guid(objectKey(owner, index))
	var filter *wfpFilter
	result, _, _ := nativeFilterGet.Call(engine, uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(&filter)))
	code := nativeStatus(result)
	if filter != nil {
		freeMemory.Call(uintptr(unsafe.Pointer(&filter)))
	}
	if code != 0x80320003 { // FWP_E_FILTER_NOT_FOUND
		t.Fatalf("filter %d exists or absence query failed: %#x", index, code)
	}
}

func nativeAssertStagedGuard(t *testing.T, engine uintptr, spec guardSpec) {
	t.Helper()
	key := guid(objectKey(spec.Key, -1))
	var sublayer *wfpSubLayer
	if err := wfpCall(nativeSubLayerGet, engine, uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(&sublayer))); err != nil {
		t.Fatal(err)
	}
	defer freeMemory.Call(uintptr(unsafe.Pointer(&sublayer)))
	if sublayer == nil || sublayer.flags != 1 || sublayer.weight != 0xffff {
		t.Fatalf("incorrect persistent sublayer: %+v", sublayer)
	}
	policy := guardFilters(spec)
	for index, rule := range policy {
		nativeAssertStagedFilter(t, engine, spec.Key, index, rule)
	}
	for index := len(policy); index < maxGuardFilters; index++ {
		nativeAssertFilterAbsent(t, engine, spec.Key, index)
	}
	t.Logf("BFE accepted and read back %d production filters", len(policy))
}

func nativeAssertStagedFilter(t *testing.T, engine uintptr, owner string, index int, rule filter) {
	t.Helper()
	key := guid(objectKey(owner, index))
	var actual *wfpFilter
	if err := wfpCall(nativeFilterGet, engine, uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(&actual))); err != nil {
		t.Fatal(err)
	}
	defer freeMemory.Call(uintptr(unsafe.Pointer(&actual)))
	if actual == nil {
		t.Fatal("BFE returned a nil filter")
	}
	action, weight := uint32(0x1001), uint64(1)
	if rule.permit {
		action, weight = 0x1002, 100
	}
	if actual.key != key || actual.layer != guid(layerKeys[rule.layer]) || actual.sublayer != guid(objectKey(owner, -1)) ||
		!nativeGuardFilterFlagsMatch(actual.flags) || actual.action.kind != action || actual.count != uint32(len(rule.conditions)) {
		t.Fatalf("%s filter %d has incorrect identity/persistence/arbitration: %+v", rule.layer, index, actual)
	}
	// Production supplies explicit UINT64 weights, not UINT8 range indexes.
	// BFE must use them unchanged, including the effective classification weight.
	// https://learn.microsoft.com/windows/win32/fwp/filter-weight-assignment
	for _, field := range []struct {
		name  string
		value wfpValue
	}{{"weight", actual.weight}, {"effectiveWeight", actual.effectiveWeight}} {
		if field.value.kind != 4 || nativeValuePointer[uint64](field.value) == nil {
			t.Fatalf("%s filter %d %s is not a nonnil UINT64: %+v", rule.layer, index, field.name, field.value)
		}
		if got := *nativeValuePointer[uint64](field.value); got != weight {
			t.Fatalf("%s filter %d %s = %d, want %d", rule.layer, index, field.name, got, weight)
		}
	}
	// In particular, permits must NOT set CLEAR_ACTION_RIGHT (hard permit).
	// This checks the staged native policy, not actual packet classification.
	for _, c := range rule.conditions {
		found := false
		for _, native := range unsafe.Slice(actual.conditions, actual.count) {
			if native.key == guid(conditionKeys[c.field]) {
				found = true
				match := uint32(0)
				if c.field == "loopback" {
					match = 6
				}
				if native.match != match {
					t.Fatalf("incorrect native match for %s: %d", c.field, native.match)
				}
				nativeAssertConditionValue(t, c, native.value)
			}
		}
		if !found {
			t.Fatalf("missing native condition %s at %s", c.field, rule.layer)
		}
	}
}

func nativeAssertConditionValue(t *testing.T, c condition, value wfpValue) {
	t.Helper()
	switch c.field {
	case "loopback":
		if value.kind != 3 || value.value != 1 {
			t.Fatalf("loopback flag changed during native round trip: %+v", value)
		}
	case "interface":
		if value.kind != 4 || nativeValuePointer[uint64](value) == nil || *nativeValuePointer[uint64](value) != c.value.(uint64) {
			t.Fatalf("LUID changed during native round trip: %+v", value)
		}
	case "protocol":
		if value.kind != 1 || value.value != uintptr(c.value.(uint8)) {
			t.Fatalf("protocol changed during native round trip: %+v", value)
		}
	case "port", "local-port":
		if value.kind != 2 || value.value != uintptr(c.value.(uint16)) {
			t.Fatalf("host-order port/ICMP value changed during native round trip: %+v", value)
		}
	case "application":
		if value.kind != 12 {
			t.Fatalf("incorrect native application ID type: %+v", value)
		}
		blob := nativeValuePointer[wfpBlob](value)
		if blob == nil || blob.size == 0 || blob.data == nil {
			t.Fatal("native application ID is empty")
		}
	}
}

func nativeAssertLayerSchema(t *testing.T, engine uintptr, policy []filter) {
	t.Helper()
	for name, text := range layerKeys {
		key := guid(text)
		var layer *nativeLayer
		if err := wfpCall(nativeLayerGet, engine, uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(&layer))); err != nil {
			t.Fatal(err)
		}
		// Free before the next layer, including assertion failures.
		func() {
			defer freeMemory.Call(uintptr(unsafe.Pointer(&layer)))
			if layer == nil || layer.key != key {
				t.Fatalf("incorrect live layer for %s", name)
			}
			fields := map[windows.GUID]uint32{}
			for _, field := range unsafe.Slice(layer.fields, layer.count) {
				if field.key != nil {
					fields[*field.key] = field.dataType
				}
			}
			for _, rule := range policy {
				if rule.layer != name {
					continue
				}
				for _, c := range rule.conditions {
					want := map[string]uint32{"loopback": 3, "interface": 4, "application": 12, "protocol": 1, "port": 2, "local-port": 2}[c.field]
					if c.field == "address" {
						want = 3 // Classify uses UINT32; filters also accept V4_ADDR_MASK.
						if strings.HasSuffix(name, "6") {
							want = 11 // BYTE_ARRAY16_TYPE; filters also accept V6_ADDR_MASK.
						}
					}
					if got, found := fields[guid(conditionKeys[c.field])]; !found || got != want {
						t.Fatalf("live SDK schema %s/%s: type %d (present %t), want %d", name, c.field, got, found, want)
					}
				}
			}
		}()
	}
}
