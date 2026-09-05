//go:build windows && (amd64 || arm64)

package winnetwork

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	wfp                   = windows.NewLazySystemDLL("fwpuclnt.dll")
	engineOpen            = wfp.NewProc("FwpmEngineOpen0")
	engineClose           = wfp.NewProc("FwpmEngineClose0")
	transactionBegin      = wfp.NewProc("FwpmTransactionBegin0")
	transactionCommit     = wfp.NewProc("FwpmTransactionCommit0")
	transactionAbort      = wfp.NewProc("FwpmTransactionAbort0")
	subLayerAdd           = wfp.NewProc("FwpmSubLayerAdd0")
	subLayerDelete        = wfp.NewProc("FwpmSubLayerDeleteByKey0")
	filterAdd             = wfp.NewProc("FwpmFilterAdd0")
	filterDelete          = wfp.NewProc("FwpmFilterDeleteByKey0")
	appIDFromFileName     = wfp.NewProc("FwpmGetAppIdFromFileName0")
	freeMemory            = wfp.NewProc("FwpmFreeMemory0")
	convertInterfaceAlias = windows.NewLazySystemDLL("iphlpapi.dll").NewProc("ConvertInterfaceAliasToLuid")
	convertInterfaceGUID  = windows.NewLazySystemDLL("iphlpapi.dll").NewProc("ConvertInterfaceLuidToGuid")
)

// The SDK value unions have pointer-sized storage; the action and filter
// context unions contain GUIDs. These layouts support amd64 and arm64 only.
type wfpDisplay struct{ name, description *uint16 }
type wfpBlob struct {
	size uint32
	data *byte
}
type wfpValue struct {
	kind  uint32
	value uintptr
}
type wfpCondition struct {
	key   windows.GUID
	match uint32
	value wfpValue
}
type wfpAction struct {
	kind uint32
	key  windows.GUID
}
type wfpFilter struct {
	key             windows.GUID
	display         wfpDisplay
	flags           uint32
	provider        *windows.GUID
	providerData    wfpBlob
	layer, sublayer windows.GUID
	weight          wfpValue
	count           uint32
	conditions      *wfpCondition
	action          wfpAction
	context         [2]uint64
	reserved        *windows.GUID
	id              uint64
	effectiveWeight wfpValue
}
type wfpSubLayer struct {
	key          windows.GUID
	display      wfpDisplay
	flags        uint32
	provider     *windows.GUID
	providerData wfpBlob
	weight       uint16
}
type v4Mask struct{ address, mask uint32 }
type v6Mask struct {
	address [16]byte
	bits    uint8
}

// Assignment checks equality (not just an upper bound), including on ARM64
// cross-builds where the runtime layout tests cannot execute.
var (
	_ [200]byte = [unsafe.Sizeof(wfpFilter{})]byte{}
	_ [40]byte  = [unsafe.Sizeof(wfpCondition{})]byte{}
	_ [72]byte  = [unsafe.Sizeof(wfpSubLayer{})]byte{}
	_ [16]byte  = [unsafe.Sizeof(wfpValue{})]byte{}
	_ [8]byte   = [unsafe.Offsetof(wfpValue{}.value)]byte{}
	_ [24]byte  = [unsafe.Offsetof(wfpCondition{}.value)]byte{}
	_ [96]byte  = [unsafe.Offsetof(wfpFilter{}.weight)]byte{}
	_ [120]byte = [unsafe.Offsetof(wfpFilter{}.conditions)]byte{}
	_ [128]byte = [unsafe.Offsetof(wfpFilter{}.action)]byte{}
	_ [152]byte = [unsafe.Offsetof(wfpFilter{}.context)]byte{}
	_ [176]byte = [unsafe.Offsetof(wfpFilter{}.id)]byte{}
	_ [64]byte  = [unsafe.Offsetof(wfpSubLayer{}.weight)]byte{}
)

// SDK identifiers: microsoft/win32metadata, generation/WinSDK/
// RecompiledIdlHeaders/um/fwpmu.h. In particular, packet and transport are
// OUTBOUND layers, not their inbound or discard counterparts.
var layerKeys = map[string]string{
	"packet4":    "1e5c9fae-8a84-4135-a331-950b54229ecd",
	"packet6":    "a3b3ab6b-3564-488c-9117-f34e82142763",
	"transport4": "09e61aea-d214-46e2-9b21-b26b0b2f28c8",
	"transport6": "e1735bde-013f-4655-b351-a49e15762df0",
	"connect4":   "c38d57d1-05a7-4c33-904f-7fbceee60e82",
	"connect6":   "4a72393b-319f-44bc-84c3-ba54dcb3b6b4",
	"accept4":    "e1cd9fe7-f4b5-4273-96c0-592e487b8650",
	"accept6":    "a3b42c97-9f04-4672-b87e-cee9c483257f",
	"forward4":   "a82acc24-4ee1-4ee1-b465-fd1d25cb10a4",
	"forward6":   "7b964818-19c7-493a-b71f-832c3684d28c",
}

var conditionKeys = map[string]string{
	"interface":   "4cd62a49-59c3-4969-b7f3-bda5d32890a4",
	"application": "d78e1e87-8644-4ea5-9437-d809ecefc971",
	"address":     "b235ae9a-1d64-49b8-a44c-5ff3d9095045",
	"port":        "c35a604d-d22b-4e1a-91b4-68f674ee674b",
	"local-port":  "0c1ba1af-5765-453f-af22-a8f791ac775b",
	"protocol":    "3971ef2b-623e-4f9a-8cb1-6e79b806b9a7",
	"loopback":    "632ce23b-5167-435c-86d7-e903684aa80c",
}

type nativeGuard struct{}

func (nativeGuard) InterfaceLUID(name string) (uint64, error) {
	alias, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	var luid uint64
	result, _, _ := convertInterfaceAlias.Call(uintptr(unsafe.Pointer(alias)), uintptr(unsafe.Pointer(&luid)))
	code := nativeStatus(result)
	if code != 0 {
		return 0, fmt.Errorf("resolve tunnel interface LUID: %w", windows.Errno(code))
	}
	if luid == 0 {
		return 0, fmt.Errorf("tunnel interface LUID is zero")
	}
	return luid, nil
}

func (nativeGuard) InterfaceGUID(luid uint64) (string, error) {
	var id windows.GUID
	result, _, _ := convertInterfaceGUID.Call(uintptr(unsafe.Pointer(&luid)), uintptr(unsafe.Pointer(&id)))
	code := nativeStatus(result)
	if code != 0 {
		return "", fmt.Errorf("resolve tunnel interface GUID: %w", windows.Errno(code))
	}
	if id == (windows.GUID{}) {
		return "", fmt.Errorf("tunnel interface GUID is zero")
	}
	return strings.ToLower(id.String()), nil
}

func guid(text string) windows.GUID {
	value, err := windows.GUIDFromString("{" + text + "}")
	if err != nil {
		panic(err)
	}
	return value
}

// Like LazyProc.Call, this wrapper must keep pointer arguments alive and off
// movable goroutine stacks until the native call returns.
//
//go:uintptrescapes
func wfpCall(proc *windows.LazyProc, args ...uintptr) error {
	result, _, _ := proc.Call(args...)
	code := nativeStatus(result)
	if code != 0 {
		return fmt.Errorf("%s: WFP error %#x", proc.Name, code)
	}
	return nil
}

func withTransaction(ctx context.Context, change func(uintptr) error) (err error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	var engine uintptr
	// A non-dynamic session is essential: engine/process closure must NOT
	// remove protection. All our objects also carry their persistent flag.
	if err := wfpCall(engineOpen, 0, 10, 0, 0, uintptr(unsafe.Pointer(&engine))); err != nil {
		return err
	}
	defer func() { err = errors.Join(err, wfpCall(engineClose, engine)) }()
	if err := wfpCall(transactionBegin, engine, 0); err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			err = errors.Join(err, wfpCall(transactionAbort, engine))
		}
	}()
	if err := change(engine); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := wfpCall(transactionCommit, engine); err != nil {
		return err
	}
	committed = true
	return nil
}

func deleteFilters(engine uintptr, owner string) error {
	for index := 0; index < maxGuardFilters; index++ {
		key := guid(objectKey(owner, index))
		result, _, _ := filterDelete.Call(engine, uintptr(unsafe.Pointer(&key)))
		code := nativeStatus(result)
		if code != 0 && code != 0x80320003 { // FWP_E_FILTER_NOT_FOUND
			return fmt.Errorf("remove owned WFP filter: %#x", code)
		}
	}
	return nil
}

func (nativeGuard) Remove(ctx context.Context, owner string) error {
	return withTransaction(ctx, func(engine uintptr) error {
		if err := deleteFilters(engine, owner); err != nil {
			return err
		}
		key := guid(objectKey(owner, -1))
		result, _, _ := subLayerDelete.Call(engine, uintptr(unsafe.Pointer(&key)))
		code := nativeStatus(result)
		if code != 0 && code != 0x80320007 { // FWP_E_SUBLAYER_NOT_FOUND
			return fmt.Errorf("remove owned WFP sublayer: %#x", code)
		}
		return nil
	})
}

func (nativeGuard) Replace(ctx context.Context, spec guardSpec) error {
	return withTransaction(ctx, func(engine uintptr) error {
		return installGuard(engine, spec)
	})
}

// installGuard only stages objects in the caller's transaction. Keeping commit
// outside this path lets native acceptance tests exercise the exact production
// FilterAdd calls without ever activating a host-wide blocking policy.
func installGuard(engine uintptr, spec guardSpec) error {
	policy := guardFilters(spec)
	if len(policy) > maxGuardFilters {
		return fmt.Errorf("too many guard filters")
	}
	path, err := windows.UTF16PtrFromString(spec.Application)
	if err != nil {
		return err
	}
	var appID *wfpBlob
	if err := wfpCall(appIDFromFileName, uintptr(unsafe.Pointer(path)), uintptr(unsafe.Pointer(&appID))); err != nil {
		return err
	}
	defer freeMemory.Call(uintptr(unsafe.Pointer(&appID)))
	name, err := windows.UTF16PtrFromString("Porta persistent full-tunnel guard")
	if err != nil {
		return err
	}
	sublayer := wfpSubLayer{
		key: guid(objectKey(spec.Key, -1)), display: wfpDisplay{name: name},
		flags: 1, weight: 0xffff, // FWPM_SUBLAYER_FLAG_PERSISTENT
	}
	result, _, _ := subLayerAdd.Call(engine, uintptr(unsafe.Pointer(&sublayer)), 0)
	code := nativeStatus(result)
	if code != 0 && code != 0x80320009 { // FWP_E_ALREADY_EXISTS
		return fmt.Errorf("add persistent WFP sublayer: %#x", code)
	}
	if err := deleteFilters(engine, spec.Key); err != nil {
		return err
	}
	for index, rule := range policy {
		if err := addGuardFilter(engine, spec.Key, index, rule, name, appID); err != nil {
			return fmt.Errorf("install %s filter %d: %w", rule.layer, index, err)
		}
	}
	return nil
}

func addGuardFilter(engine uintptr, owner string, index int, rule filter, name *uint16, appID *wfpBlob) error {
	var pinned runtime.Pinner
	defer pinned.Unpin()
	conditions := nativeConditions(rule.conditions, appID, &pinned)
	weight := uint64(1)
	action := uint32(0x1001) // FWP_ACTION_BLOCK; hard block by default
	if rule.permit {
		weight = 100
		action = 0x1002 // FWP_ACTION_PERMIT; soft permit by default
	}
	pinned.Pin(&weight)
	filter := wfpFilter{
		key: guid(objectKey(owner, index)), display: wfpDisplay{name: name},
		flags: 1, // PERSISTENT, never CLEAR_ACTION_RIGHT on a permit
		layer: guid(layerKeys[rule.layer]), sublayer: guid(objectKey(owner, -1)),
		weight: wfpValue{kind: 4, value: uintptr(unsafe.Pointer(&weight))},
		count:  uint32(len(conditions)), action: wfpAction{kind: action},
	}
	if len(conditions) != 0 {
		filter.conditions = &conditions[0]
	}
	return wfpCall(filterAdd, engine, uintptr(unsafe.Pointer(&filter)), 0, 0)
}

// Pointer-valued SDK unions are stored as uintptr, invisible to Go's GC. Pin
// their Go allocations BEFORE converting them, for the entire FilterAdd call.
func nativeConditions(input []condition, appID *wfpBlob, pinned *runtime.Pinner) []wfpCondition {
	var conditions []wfpCondition
	for _, c := range input {
		value := wfpCondition{key: guid(conditionKeys[c.field])}
		switch c.field {
		case "loopback":
			value.match = 6                           // FWP_MATCH_FLAGS_ALL_SET
			value.value = wfpValue{kind: 3, value: 1} // FWP_CONDITION_FLAG_IS_LOOPBACK
		case "interface":
			luid := new(uint64)
			*luid = c.value.(uint64)
			pinned.Pin(luid)
			value.value = wfpValue{kind: 4, value: uintptr(unsafe.Pointer(luid))}
		case "application":
			value.value = wfpValue{kind: 12, value: uintptr(unsafe.Pointer(appID))}
		case "protocol":
			value.value = wfpValue{kind: 1, value: uintptr(c.value.(uint8))}
		case "port", "local-port":
			// FWPM_CONDITION_ICMP_TYPE/CODE alias LOCAL_PORT/REMOTE_PORT.
			// WFP UINT16 ports (and ICMP values) use host order, not htons.
			value.value = wfpValue{kind: 2, value: uintptr(c.value.(uint16))}
		case "address":
			prefix := c.value.(netip.Prefix)
			if prefix.Addr().Is4() {
				ip := prefix.Addr().As4()
				mask := &v4Mask{address: binary.BigEndian.Uint32(ip[:]), mask: ^uint32(0) << (32 - prefix.Bits())}
				pinned.Pin(mask)
				value.value = wfpValue{kind: 0x100, value: uintptr(unsafe.Pointer(mask))}
			} else {
				mask := &v6Mask{address: prefix.Addr().As16(), bits: uint8(prefix.Bits())}
				pinned.Pin(mask)
				value.value = wfpValue{kind: 0x101, value: uintptr(unsafe.Pointer(mask))}
			}
		default:
			panic("unsupported WFP condition")
		}
		conditions = append(conditions, value)
	}
	return conditions
}
