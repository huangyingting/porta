//go:build linux

package linuxnetwork

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

const routeProtocol = 186

type endpointState struct {
	IP   string `json:"ip"`
	Port int    `json:"port"`
}

func (e endpointState) prefix() string {
	ip := netip.MustParseAddr(e.IP)
	return netip.PrefixFrom(ip, ip.BitLen()).String()
}

type networkState struct {
	Version   int             `json:"version"`
	Table     string          `json:"table"`
	Metric    int             `json:"metric"`
	Interface string          `json:"interface,omitempty"`
	Index     int             `json:"index,omitempty"`
	Endpoints []endpointState `json:"endpoints"`
	Undo      []action        `json:"undo"`
}

// Every action is written and fsynced BEFORE the corresponding mutation. Undo
// checks current kernel state, so an interrupted command can be retried without
// guessing whether it reached the kernel.
type action struct {
	Kind          string `json:"kind"`
	Interface     string `json:"interface"`
	Index         int    `json:"index"`
	LinkKind      string `json:"link_kind,omitempty"`
	LinkAddress   string `json:"link_address,omitempty"`
	LinkAlias     string `json:"link_alias,omitempty"`
	PreviousAlias string `json:"previous_alias,omitempty"`
	Family        int    `json:"family,omitempty"`
	Destination   string `json:"destination,omitempty"`
	Gateway       string `json:"gateway,omitempty"`
	Address       string `json:"address,omitempty"`
	MTU           int    `json:"mtu,omitempty"`
	WasUp         bool   `json:"was_up,omitempty"`
}

func (r *Runner) openState() error {
	if r.statePath == "" || filepath.Base(r.statePath) == "." {
		return errors.New("network recovery state path is required")
	}
	absolute, err := filepath.Abs(r.statePath)
	if err != nil {
		return err
	}
	r.statePath = absolute
	if err := os.MkdirAll(filepath.Dir(r.statePath), 0700); err != nil {
		return fmt.Errorf("create network state directory: %w", err)
	}
	info, err := os.Lstat(filepath.Dir(r.statePath))
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm()&0022 != 0 {
		return errors.New("network state directory must be a non-symlink directory not writable by other users")
	}
	var directoryStat unix.Stat_t
	if err := unix.Stat(filepath.Dir(r.statePath), &directoryStat); err != nil {
		return err
	}
	if int(directoryStat.Uid) != os.Geteuid() {
		return errors.New("network state directory must be owned by the current user")
	}
	return r.ensureLock()
}

func (r *Runner) readState() error {
	fd, err := unix.Open(r.statePath, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, os.ErrNotExist) {
		r.state = networkState{}
		return nil
	}
	if err != nil {
		return fmt.Errorf("open network recovery state: %w", err)
	}
	file := os.NewFile(uintptr(fd), r.statePath)
	defer file.Close()
	if err := privateFile(file); err != nil {
		return err
	}
	decoder := json.NewDecoder(io.LimitReader(file, 1024*1024))
	decoder.DisallowUnknownFields()
	var state networkState
	if err := decoder.Decode(&state); err != nil {
		return fmt.Errorf("decode network recovery state: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return errors.New("trailing data in network recovery state")
	}
	if err := state.validate(); err != nil {
		return err
	}
	r.state = state
	return nil
}

func privateFile(file *os.File) error {
	var stat unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &stat); err != nil {
		return err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0077 != 0 || int(stat.Uid) != os.Geteuid() || stat.Nlink != 1 {
		return errors.New("network recovery files must be private, singly linked regular files owned by the current user")
	}
	return nil
}

func (r *Runner) ensureLock() error {
	if r.lock != nil {
		return nil
	}
	if r.statePath == "" {
		return errors.New("initialize Linux networking with NewRunner")
	}
	fd, err := unix.Open(r.statePath+".lock", unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return fmt.Errorf("open network state lock: %w", err)
	}
	file := os.NewFile(uintptr(fd), r.statePath+".lock")
	if err := privateFile(file); err != nil {
		_ = file.Close()
		return err
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = file.Close()
		return fmt.Errorf("network recovery state is in use by another process: %w", err)
	}
	r.lock = file
	if err := r.readState(); err != nil {
		_ = r.releaseLock()
		return err
	}
	return nil
}

func (r *Runner) releaseLock() error {
	if r.lock == nil {
		return nil
	}
	err := r.lock.Close()
	r.lock = nil
	return err
}

func (r *Runner) initializeState() error {
	var id [8]byte
	if _, err := rand.Read(id[:]); err != nil {
		return err
	}
	r.state = networkState{Version: 2, Table: "porta_" + hex.EncodeToString(id[:]), Metric: 40000 + (int(id[0]) << 4) + int(id[1])}
	if err := r.persist(); err != nil {
		r.state = networkState{}
		return err
	}
	return nil
}

func (r *Runner) persist() error {
	data, err := json.Marshal(r.state)
	if err != nil {
		return err
	}
	var id [8]byte
	if _, err := rand.Read(id[:]); err != nil {
		return err
	}
	pending := r.statePath + ".pending-" + hex.EncodeToString(id[:])
	file, err := os.OpenFile(pending, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("create network journal: %w", err)
	}
	defer os.Remove(pending)
	_, writeErr := file.Write(data)
	syncErr := file.Sync()
	closeErr := file.Close()
	if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
		return fmt.Errorf("persist network journal: %w", err)
	}
	if err := os.Rename(pending, r.statePath); err != nil {
		return fmt.Errorf("replace network journal: %w", err)
	}
	return r.syncDirectory()
}

func (r *Runner) syncDirectory() error {
	directory, err := os.Open(filepath.Dir(r.statePath))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func (r *Runner) removeState() error {
	if err := os.Remove(r.statePath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove network recovery state: %w", err)
	}
	return r.syncDirectory()
}

func (r *Runner) record(a action) error {
	if len(r.state.Undo) >= 2048 {
		return errors.New("network journal action limit reached; explicit cleanup is required")
	}
	r.state.Undo = append(r.state.Undo, a)
	if err := r.persist(); err != nil {
		r.state.Undo = r.state.Undo[:len(r.state.Undo)-1]
		return err
	}
	return nil
}

func (r *Runner) hasAction(kind, iface, address string) bool {
	for _, a := range r.state.Undo {
		if a.Kind == kind && a.Interface == iface && a.Address == address {
			return true
		}
	}
	return false
}

func (s networkState) validate() error {
	if s.Version != 2 || len(s.Table) != len("porta_")+16 || !strings.HasPrefix(s.Table, "porta_") {
		return errors.New("invalid network journal version or nftables table")
	}
	if _, err := hex.DecodeString(strings.TrimPrefix(s.Table, "porta_")); err != nil {
		return errors.New("invalid network journal table")
	}
	if s.Metric < 40000 || s.Metric > 50000 || (s.Interface != "" && (!validInterface(s.Interface) || s.Index <= 0)) {
		return errors.New("invalid network journal interface or route metric")
	}
	if len(s.Endpoints) > 256 || len(s.Undo) > 2048 {
		return errors.New("network journal exceeds recovery limits")
	}
	for _, e := range s.Endpoints {
		ip, err := netip.ParseAddr(e.IP)
		if err != nil {
			return errors.New("invalid network journal endpoint")
		}
		address := &net.TCPAddr{IP: net.IP(ip.AsSlice()), Port: e.Port}
		parsed, err := parseEndpoint(address)
		if err != nil || parsed != e {
			return errors.New("invalid network journal endpoint")
		}
	}
	for _, a := range s.Undo {
		if !validInterface(a.Interface) || a.Index <= 0 {
			return errors.New("invalid network journal action interface")
		}
		if len(a.LinkKind) > 64 || len(a.LinkAddress) > 64 ||
			len(a.LinkAlias) > 128 || len(a.PreviousAlias) > 128 {
			return errors.New("invalid network journal link identity")
		}
		if a.LinkAddress != "" {
			if _, err := net.ParseMAC(a.LinkAddress); err != nil {
				return errors.New("invalid network journal link address")
			}
		}
		if a.Kind != "escape" && (a.LinkAlias != "porta:"+s.Table || a.LinkKind != "tun") {
			return errors.New("network journal action lacks tunnel ownership")
		}
		switch a.Kind {
		case "alias":
			if a.PreviousAlias != "" {
				return errors.New("invalid network journal link alias")
			}
		case "link":
			if a.MTU < 68 || a.MTU > 65535 {
				return errors.New("invalid network journal MTU")
			}
		case "address":
			prefix, err := netip.ParsePrefix(a.Address)
			if err != nil || !prefix.Addr().Is4() || !prefix.Addr().IsGlobalUnicast() {
				return errors.New("invalid network journal address")
			}
		case "route", "escape", "dns-route":
			prefix, err := netip.ParsePrefix(a.Destination)
			if err != nil || (a.Family != 4 && a.Family != 6) || (prefix.Addr().Is4() != (a.Family == 4)) {
				return errors.New("invalid network journal route")
			}
			if a.Kind == "route" && a.Destination != "0.0.0.0/1" && a.Destination != "128.0.0.0/1" {
				return errors.New("invalid network journal tunnel route")
			}
			if a.Kind == "escape" && prefix.Bits() != prefix.Addr().BitLen() {
				return errors.New("invalid network journal escape route")
			}
			if a.Kind == "dns-route" && (a.Family != 4 || prefix.Bits() != 32 || !prefix.Addr().IsGlobalUnicast()) {
				return errors.New("invalid network journal DNS route")
			}
			if a.Gateway != "" {
				gateway, err := netip.ParseAddr(a.Gateway)
				if err != nil || gateway.Is4() != (a.Family == 4) {
					return errors.New("invalid network journal gateway")
				}
			}
		case "dns":
		default:
			return errors.New("invalid network journal action: " + strconv.Quote(a.Kind))
		}
	}
	return nil
}
