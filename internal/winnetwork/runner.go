package winnetwork

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/huangyingting/porta/internal/tunnel"
)

var ErrStateInUse = errors.New("another Porta process owns this network state; disconnect or close that process first")

const (
	exactOwnershipStateVersion = 2
	nativeMTUStateVersion      = 3
)

type Runner struct {
	mu                 sync.Mutex
	statePath          string
	state              networkState
	protected          bool
	lock               *os.File
	guard              guardEngine
	readInterfaceMTU   func(uint64) (uint32, error)
	updateInterfaceMTU func(uint64, uint32) error
	runCommand         func(context.Context, ...string) (string, error)
}

type routeState struct {
	Kind      string `json:"kind,omitempty"`
	Prefix    string `json:"prefix"`
	Interface int    `json:"interface_index"`
	GUID      string `json:"interface_guid"`
	NextHop   string `json:"next_hop"`
	Metric    int    `json:"metric"`
}

type dnsState struct {
	Interface int      `json:"interface_index"`
	Automatic bool     `json:"automatic"`
	Original  []string `json:"original"`
	Applied   string   `json:"applied"`
	Pending   string   `json:"pending"`
}

type mtuState struct {
	Original uint32 `json:"original"`
	Applied  int    `json:"applied"`
	Pending  int    `json:"pending"`
}

type networkState struct {
	Version        int          `json:"version"`
	Interface      string       `json:"interface"`
	ServerIP       string       `json:"server_ip"`
	GuardKey       string       `json:"guard_key,omitempty"`
	Endpoint       endpoint     `json:"endpoint"`
	Application    string       `json:"application,omitempty"`
	InterfaceLUID  uint64       `json:"interface_luid,omitempty"`
	InterfaceIndex int          `json:"interface_index,omitempty"`
	InterfaceGUID  string       `json:"interface_guid,omitempty"`
	OriginalDHCP   string       `json:"original_dhcp,omitempty"`
	Addresses      []string     `json:"addresses,omitempty"`
	Routes         []routeState `json:"routes,omitempty"`
	DNS            *dnsState    `json:"dns,omitempty"`
	MTU            *mtuState    `json:"mtu,omitempty"`
}

func NewRunner(statePath string) (*Runner, error) {
	if strings.TrimSpace(statePath) == "" {
		return nil, errors.New("network state path is required")
	}
	path, err := filepath.Abs(statePath)
	if err != nil {
		return nil, err
	}
	runner := &Runner{
		statePath:          filepath.Clean(path),
		guard:              nativeGuard{},
		readInterfaceMTU:   nativeInterfaceMTU,
		updateInterfaceMTU: setNativeInterfaceMTU,
	}
	if err := runner.reloadLocked(); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return runner, nil
}

// Protected reports only activation confirmed by this Runner, never merely the
// existence of a journal left by another process. External administrator/WFP
// changes and the boot interval before BFE starts are outside this guarantee.
func (r *Runner) Protected() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.protected
}

// NeedsCleanup reports owned recovery state, not proof of active filtering.
func (r *Runner) NeedsCleanup() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.state.Interface != "" || r.state.GuardKey != ""
}

// RecoveryEndpoints exposes the journaled literal address without doing DNS or
// claiming that persisted state alone proves activation in this process.
func (r *Runner) RecoveryEndpoints() []net.Addr {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.state.GuardKey == "" {
		return nil
	}
	address := net.TCPAddrFromAddrPort(netip.AddrPortFrom(r.state.Endpoint.IP, r.state.Endpoint.Port))
	if _, err := parseEndpoint(address); err != nil {
		// A non-empty invalid result makes clientapp reject recovery instead of
		// treating a damaged guarded journal as permission to bootstrap DNS.
		return []net.Addr{nil}
	}
	return []net.Addr{address}
}

// Prepare activates after the first authenticated bootstrap, before VPN route
// setup. On guarded reconnection it pins a literal endpoint BEFORE dialing.
// It may run before the TUN exists; no payload interface is then exempt.
// No physical DNS exemption is created. Errors retain the guard until Down.
func (r *Runner) Prepare(ctx context.Context, interfaceName string, remoteAddr net.Addr) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.prepareLocked(ctx, interfaceName, remoteAddr, false)
}

func (r *Runner) prepareLocked(ctx context.Context, interfaceName string, remoteAddr net.Addr, requireInterface bool) error {
	if strings.TrimSpace(interfaceName) == "" {
		return errors.New("tunnel interface name is required")
	}
	remote, err := parseEndpoint(remoteAddr)
	if err != nil {
		return err
	}
	if err := r.acquireLocked(); err != nil {
		return err
	}
	if r.state.Interface != "" && r.state.Interface != interfaceName {
		return errors.New("saved network state belongs to a different interface; explicitly disconnect it first")
	}
	if r.state.Interface != "" && r.state.Version != exactOwnershipStateVersion && r.state.Version != nativeMTUStateVersion {
		return errors.New("legacy network journal lacks exact ownership; restore it with the client version that created it before upgrading")
	}
	if r.guard == nil {
		r.guard = nativeGuard{}
	}
	var luid uint64
	var interfaceGUID string
	if requireInterface {
		luid, err = r.guard.InterfaceLUID(interfaceName)
		if err != nil {
			return err
		}
		interfaceGUID, err = r.guard.InterfaceGUID(luid)
		if err != nil {
			return err
		}
		if previousLUID := r.state.InterfaceLUID; previousLUID != 0 && (previousLUID != luid || !strings.EqualFold(r.state.InterfaceGUID, interfaceGUID)) {
			_, retireErr := r.invoke(ctx, "retire-interface", r.statePath)
			if err := errors.Join(retireErr, r.reloadLocked()); err != nil {
				return fmt.Errorf("retire replaced tunnel interface while retaining protection: %w", err)
			}
			if r.state.InterfaceLUID != 0 {
				return errors.New("previous tunnel interface still exists; explicitly disconnect it first")
			}
		}
	}
	next := r.state
	if next.Version == 0 {
		next.Version = exactOwnershipStateVersion
	}
	next.Interface = interfaceName
	next.ServerIP = remote.IP.String()
	next.Endpoint = remote
	if next.GuardKey == "" {
		next.GuardKey = objectKey(strings.ToLower(r.statePath), -2)
	}
	application, err := os.Executable()
	if err != nil {
		return fmt.Errorf("determine transport executable: %w", err)
	}
	next.Application = application
	if requireInterface {
		next.InterfaceLUID = luid
		next.InterfaceGUID = interfaceGUID
	}
	previous := r.state
	r.state = next
	if err := r.persistLocked(); err != nil {
		r.state = previous
		return err
	}
	if err := r.guard.Replace(ctx, guardSpec{
		Key: next.GuardKey, InterfaceLUID: luid,
		Endpoint: remote, Application: next.Application,
	}); err != nil {
		return fmt.Errorf("activate persistent Windows leak protection (explicit Disconnect restores owned state): %w", err)
	}
	r.protected = true
	if _, err := r.invoke(ctx, "prepare", r.statePath); err != nil {
		return errors.Join(err, r.reloadLocked())
	}
	return r.reloadLocked()
}

func (r *Runner) Up(ctx context.Context, interfaceName string, remoteAddr net.Addr, lease tunnel.Lease) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !lease.Address.IsValid() || !lease.Address.Addr().Is4() || !lease.Address.Addr().IsGlobalUnicast() {
		return errors.New("full tunnel requires a valid IPv4 lease")
	}
	if !lease.DNS.IsValid() || !lease.DNS.Is4() || !lease.DNS.IsGlobalUnicast() {
		return errors.New("full tunnel requires an IPv4 DNS resolver reachable through the tunnel")
	}
	if lease.MTU < 576 || lease.MTU > 9000 {
		return fmt.Errorf("tunnel MTU %d is outside 576..9000", lease.MTU)
	}
	remote, err := parseEndpoint(remoteAddr)
	if err != nil {
		return err
	}
	if lease.DNS == remote.IP {
		return errors.New("tunnel DNS cannot be the transport endpoint (its host route bypasses the tunnel)")
	}
	if err := r.prepareLocked(ctx, interfaceName, remoteAddr, true); err != nil {
		return err
	}
	if _, err := r.invoke(ctx, "configure-interface", r.statePath, lease.Address.String(), lease.DNS.String(), fmt.Sprint(lease.MTU)); err != nil {
		return errors.Join(err, r.reloadLocked())
	}
	if err := r.reloadLocked(); err != nil {
		return err
	}
	if err := r.applyMTULocked(lease.MTU); err != nil {
		return err
	}
	_, upErr := r.invoke(ctx, "up", r.statePath, lease.Address.String(), lease.DNS.String(), fmt.Sprint(lease.MTU))
	// Network setup journals ownership BEFORE each mutation. Never automatically
	// call Down here: a lease/configuration failure must not release protection.
	return errors.Join(upErr, r.reloadLocked())
}

func (r *Runner) Reconfigure(ctx context.Context, interfaceName string, remoteAddr net.Addr, lease tunnel.Lease) error {
	return r.Up(ctx, interfaceName, remoteAddr, lease)
}

// Down is intentional Disconnect, not transport-failure cleanup. Network state
// is restored first; only successful restoration permits guard removal.
func (r *Runner) Down(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.acquireLocked(); err != nil {
		return err
	}
	if r.state.Interface == "" && r.state.GuardKey == "" {
		if err := os.Remove(r.statePath + ".pending"); err != nil && !errors.Is(err, os.ErrNotExist) {
			return errors.Join(fmt.Errorf("remove pending network state: %w", err), r.releaseLocked())
		}
		return r.releaseLocked()
	}
	if err := r.restoreMTULocked(); err != nil {
		return err
	}
	_, downErr := r.invoke(ctx, "down", r.statePath)
	if err := errors.Join(downErr, r.reloadLocked()); err != nil {
		return err
	}
	if r.state.GuardKey != "" {
		if r.guard == nil {
			r.guard = nativeGuard{}
		}
		if err := r.guard.Remove(ctx, r.state.GuardKey); err != nil {
			return fmt.Errorf("remove persistent leak protection: %w", err)
		}
		r.protected = false
	}
	if err := os.Remove(r.statePath + ".pending"); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove pending network state: %w", err)
	}
	if err := os.Remove(r.statePath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove network state: %w", err)
	}
	r.state = networkState{}
	return r.releaseLocked()
}

func (r *Runner) applyMTULocked(mtu int) error {
	if r.state.InterfaceLUID == 0 {
		return errors.New("tunnel interface identity is unavailable for native MTU configuration")
	}
	if r.readInterfaceMTU == nil || r.updateInterfaceMTU == nil {
		return errors.New("native Windows MTU configuration is unavailable")
	}
	if r.state.MTU == nil {
		original, err := r.readInterfaceMTU(r.state.InterfaceLUID)
		if err != nil {
			return fmt.Errorf("snapshot tunnel interface MTU with Windows IP Helper API: %w", err)
		}
		if original == 0 {
			return errors.New("Windows IP Helper API returned a zero tunnel interface MTU")
		}
		r.state.MTU = &mtuState{Original: original}
	}
	r.state.Version = nativeMTUStateVersion
	r.state.MTU.Pending = mtu
	if err := r.persistLocked(); err != nil {
		return err
	}
	if err := r.updateInterfaceMTU(r.state.InterfaceLUID, uint32(mtu)); err != nil {
		return fmt.Errorf("apply tunnel interface MTU with Windows IP Helper API: %w", err)
	}
	r.state.MTU.Applied = mtu
	r.state.MTU.Pending = 0
	return r.persistLocked()
}

func (r *Runner) restoreMTULocked() error {
	if r.state.MTU == nil || r.state.InterfaceLUID == 0 || r.state.InterfaceGUID == "" {
		return nil
	}
	if r.guard == nil {
		r.guard = nativeGuard{}
	}
	currentGUID, err := r.guard.InterfaceGUID(r.state.InterfaceLUID)
	if err != nil || !strings.EqualFold(currentGUID, r.state.InterfaceGUID) {
		// PowerShell verifies adapter identity independently and retires the
		// ownership record if the original adapter no longer exists.
		return nil
	}
	if r.readInterfaceMTU == nil || r.updateInterfaceMTU == nil {
		return errors.New("native Windows MTU restoration is unavailable")
	}
	current, err := r.readInterfaceMTU(r.state.InterfaceLUID)
	if err != nil {
		return fmt.Errorf("read tunnel interface MTU for restoration with Windows IP Helper API: %w", err)
	}
	owned := (r.state.MTU.Applied != 0 && current == uint32(r.state.MTU.Applied)) ||
		(r.state.MTU.Pending != 0 && current == uint32(r.state.MTU.Pending))
	if owned {
		if err := r.updateInterfaceMTU(r.state.InterfaceLUID, r.state.MTU.Original); err != nil {
			return fmt.Errorf("restore tunnel interface MTU with Windows IP Helper API: %w", err)
		}
	}
	r.state.MTU = nil
	return r.persistLocked()
}

func (r *Runner) acquireLocked() error {
	if r.lock != nil {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(r.statePath), 0o700); err != nil {
		return fmt.Errorf("create network ownership directory: %w", err)
	}
	lock, err := lockJournal(r.statePath + ".lock")
	if err != nil {
		return err
	}
	r.lock = lock
	if err := r.reloadLocked(); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			r.state = networkState{}
		} else {
			return errors.Join(err, r.releaseLocked())
		}
	}
	return nil
}

func (r *Runner) releaseLocked() error {
	if r.lock == nil {
		return nil
	}
	err := r.lock.Close()
	r.lock = nil
	// Never delete the sidecar: unlink/recreate would allow locks on different
	// files for the same journal. Process death closes this handle, not WFP.
	return err
}

func (r *Runner) invoke(ctx context.Context, arguments ...string) (result string, runErr error) {
	if r.runCommand != nil {
		return r.runCommand(ctx, arguments...)
	}
	if runtime.GOOS != "windows" {
		return "", errors.New("Windows network configuration is unavailable on this platform")
	}
	systemRoot := os.Getenv("SystemRoot")
	if systemRoot == "" {
		return "", errors.New("SystemRoot is unavailable")
	}
	powerShell := filepath.Join(systemRoot, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
	scriptPath, err := writeNetworkScript(filepath.Dir(r.statePath))
	if err != nil {
		return "", err
	}
	defer func() {
		if err := os.Remove(scriptPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			runErr = errors.Join(runErr, fmt.Errorf("remove network helper: %w", err))
		}
	}()
	commandCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	args := append([]string{"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", scriptPath}, arguments...)
	command := exec.CommandContext(commandCtx, powerShell, args...)
	hideNetworkCommand(command)
	output, err := command.CombinedOutput()
	if err != nil {
		if commandCtx.Err() != nil {
			return "", fmt.Errorf("network helper: %w", commandCtx.Err())
		}
		return "", fmt.Errorf("network helper failed: %s: %w", strings.TrimSpace(string(output)), err)
	}
	return string(output), nil
}

func writeNetworkScript(directory string) (path string, err error) {
	file, err := os.CreateTemp(directory, ".porta-network-*.ps1")
	if err != nil {
		return "", fmt.Errorf("create network helper: %w", err)
	}
	path = file.Name()
	_, writeErr := file.WriteString("\xef\xbb\xbf" + networkScript)
	if err := errors.Join(writeErr, file.Close()); err != nil {
		_ = os.Remove(path)
		return "", fmt.Errorf("write network helper: %w", err)
	}
	return path, nil
}

//go:embed network.ps1
var networkScript string

func (r *Runner) reloadLocked() error {
	file, err := os.Open(r.statePath)
	if err != nil {
		return fmt.Errorf("read network helper state: %w", err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 1<<20+1))
	if err != nil {
		return fmt.Errorf("read network helper state: %w", err)
	}
	if len(data) > 1<<20 {
		return errors.New("network recovery journal exceeds 1 MiB")
	}
	var saved networkState
	if err := json.Unmarshal(data, &saved); err != nil {
		return fmt.Errorf("decode network helper state: %w", err)
	}
	if err := saved.validate(); err != nil {
		return fmt.Errorf("invalid network recovery journal: %w", err)
	}
	r.state = saved
	return nil
}

func (r *Runner) persistLocked() error {
	data, err := json.Marshal(r.state)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(r.statePath), 0o700); err != nil {
		return fmt.Errorf("create network state directory: %w", err)
	}
	pending := r.statePath + ".pending"
	defer os.Remove(pending)
	file, err := os.OpenFile(pending, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("write network state: %w", err)
	}
	_, writeErr := file.Write(data)
	syncErr := file.Sync()
	closeErr := file.Close()
	if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
		return fmt.Errorf("flush network state: %w", err)
	}
	if err := replaceJournal(pending, r.statePath); err != nil {
		return fmt.Errorf("replace network state: %w", err)
	}
	return nil
}
