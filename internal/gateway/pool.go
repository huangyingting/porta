package gateway

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
)

var ErrPoolExhausted = errors.New("address pool is exhausted")

type Lease struct {
	Address    netip.Addr
	PrefixBits int
	Gateway    netip.Addr
	generation uint64
	clientID   string
}

func (l Lease) Prefix() netip.Prefix { return netip.PrefixFrom(l.Address, l.PrefixBits) }

type leaseRecord struct {
	address    netip.Addr
	generation uint64
	active     bool
}

type activeLeaseGroup struct {
	id         string
	generation uint64
	references int
}

type Pool struct {
	mu        sync.Mutex
	prefix    netip.Prefix
	gateway   netip.Addr
	byClient  map[string]leaseRecord
	byAddr    map[netip.Addr]string
	groups    map[string]activeLeaseGroup
	nextGen   uint64
	statePath string
}

func NewPool(cidr string) (*Pool, error) {
	return newPool(cidr, "")
}

func NewPersistentPool(cidr, statePath string) (*Pool, error) {
	if statePath == "" {
		return nil, errors.New("lease state path is required")
	}
	return newPool(cidr, statePath)
}

func newPool(cidr, statePath string) (*Pool, error) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return nil, fmt.Errorf("parse pool: %w", err)
	}
	prefix = prefix.Masked()
	if !prefix.Addr().Is4() {
		return nil, errors.New("the MVP address pool must be IPv4")
	}
	if prefix.Bits() < 16 || prefix.Bits() > 30 {
		return nil, fmt.Errorf("pool prefix /%d is outside /16../30", prefix.Bits())
	}
	gateway := prefix.Addr().Next()
	pool := &Pool{
		prefix:    prefix,
		gateway:   gateway,
		byClient:  make(map[string]leaseRecord),
		byAddr:    make(map[netip.Addr]string),
		groups:    make(map[string]activeLeaseGroup),
		statePath: statePath,
	}
	if statePath != "" {
		if err := pool.loadState(); err != nil {
			return nil, err
		}
	}
	return pool, nil
}

func (p *Pool) Acquire(clientID string) (Lease, error) {
	return p.acquire(clientID, "")
}

func (p *Pool) AcquireGroup(clientID, groupID string) (Lease, error) {
	if groupID == "" {
		return Lease{}, errors.New("lease group ID is required")
	}
	return p.acquire(clientID, groupID)
}

func (p *Pool) acquire(clientID, groupID string) (Lease, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if group, ok := p.groups[clientID]; ok && group.id == groupID && groupID != "" {
		record, exists := p.byClient[clientID]
		if exists && record.generation == group.generation && record.active {
			group.references++
			p.groups[clientID] = group
			return p.lease(clientID, record), nil
		}
	}

	p.nextGen++
	if existing, ok := p.byClient[clientID]; ok {
		previous := existing
		previousGroup, hadPreviousGroup := p.groups[clientID]
		existing.generation = p.nextGen
		existing.active = true
		p.byClient[clientID] = existing
		if err := p.persistStateLocked(); err != nil {
			p.byClient[clientID] = previous
			if hadPreviousGroup {
				p.groups[clientID] = previousGroup
			}
			return Lease{}, err
		}
		p.activateGroup(clientID, groupID, existing.generation)
		return p.lease(clientID, existing), nil
	}

	last := lastAddress(p.prefix)
	for candidate := p.gateway.Next(); candidate.IsValid() && candidate.Compare(last) < 0; candidate = candidate.Next() {
		if _, inUse := p.byAddr[candidate]; inUse {
			continue
		}
		record := leaseRecord{address: candidate, generation: p.nextGen, active: true}
		p.byClient[clientID] = record
		p.byAddr[candidate] = clientID
		if err := p.persistStateLocked(); err != nil {
			delete(p.byClient, clientID)
			delete(p.byAddr, candidate)
			return Lease{}, err
		}
		p.activateGroup(clientID, groupID, record.generation)
		return p.lease(clientID, record), nil
	}
	var (
		reclaimClient string
		reclaimRecord leaseRecord
	)
	for existingClient, record := range p.byClient {
		if record.active || (reclaimClient != "" && record.generation >= reclaimRecord.generation) {
			continue
		}
		reclaimClient = existingClient
		reclaimRecord = record
	}
	if reclaimClient != "" {
		delete(p.byClient, reclaimClient)
		record := leaseRecord{address: reclaimRecord.address, generation: p.nextGen, active: true}
		p.byClient[clientID] = record
		p.byAddr[record.address] = clientID
		if err := p.persistStateLocked(); err != nil {
			delete(p.byClient, clientID)
			p.byClient[reclaimClient] = reclaimRecord
			p.byAddr[reclaimRecord.address] = reclaimClient
			return Lease{}, err
		}
		p.activateGroup(clientID, groupID, record.generation)
		return p.lease(clientID, record), nil
	}
	return Lease{}, ErrPoolExhausted
}

func (p *Pool) Release(lease Lease) {
	p.mu.Lock()
	defer p.mu.Unlock()
	record, ok := p.byClient[lease.clientID]
	if !ok || record.generation != lease.generation {
		return
	}
	if group, exists := p.groups[lease.clientID]; exists && group.generation == lease.generation {
		group.references--
		if group.references > 0 {
			p.groups[lease.clientID] = group
			return
		}
		delete(p.groups, lease.clientID)
	}
	record.active = false
	p.byClient[lease.clientID] = record
}

func (p *Pool) activateGroup(clientID, groupID string, generation uint64) {
	if groupID == "" {
		delete(p.groups, clientID)
		return
	}
	p.groups[clientID] = activeLeaseGroup{
		id:         groupID,
		generation: generation,
		references: 1,
	}
}

func (p *Pool) Gateway() netip.Addr { return p.gateway }

type persistedLease struct {
	Address    string `json:"address"`
	Generation uint64 `json:"generation"`
}

type poolState struct {
	Version int                       `json:"version"`
	Leases  map[string]persistedLease `json:"leases"`
}

func (p *Pool) loadState() error {
	data, err := os.ReadFile(p.statePath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read lease state: %w", err)
	}
	var header struct {
		Version int `json:"version"`
	}
	if err := json.Unmarshal(data, &header); err != nil {
		return fmt.Errorf("decode lease state: %w", err)
	}
	switch header.Version {
	case 1:
		var legacy struct {
			Leases map[string]string `json:"leases"`
		}
		if err := json.Unmarshal(data, &legacy); err != nil {
			return fmt.Errorf("decode legacy lease state: %w", err)
		}
		clientIDs := make([]string, 0, len(legacy.Leases))
		for clientID := range legacy.Leases {
			clientIDs = append(clientIDs, clientID)
		}
		sort.Strings(clientIDs)
		for _, clientID := range clientIDs {
			p.nextGen++
			if err := p.restoreLease(clientID, legacy.Leases[clientID], p.nextGen); err != nil {
				return err
			}
		}
		return nil
	case 2:
		var state poolState
		if err := json.Unmarshal(data, &state); err != nil {
			return fmt.Errorf("decode lease state: %w", err)
		}
		for clientID, lease := range state.Leases {
			if lease.Generation == 0 {
				return fmt.Errorf("lease state contains zero generation for %q", clientID)
			}
			if err := p.restoreLease(clientID, lease.Address, lease.Generation); err != nil {
				return err
			}
			if lease.Generation > p.nextGen {
				p.nextGen = lease.Generation
			}
		}
		return nil
	default:
		return fmt.Errorf("unsupported lease state version %d", header.Version)
	}
}

func (p *Pool) restoreLease(clientID, value string, generation uint64) error {
	last := lastAddress(p.prefix)
	if !ValidClientID(clientID) {
		return fmt.Errorf("lease state contains invalid client ID %q", clientID)
	}
	address, err := netip.ParseAddr(value)
	if err != nil || !address.Is4() || !p.prefix.Contains(address) ||
		address.Compare(p.gateway) <= 0 || address.Compare(last) >= 0 {
		return fmt.Errorf("lease state contains invalid address %q for %q", value, clientID)
	}
	if previous, exists := p.byAddr[address]; exists {
		return fmt.Errorf("lease state assigns %s to both %q and %q", address, previous, clientID)
	}
	record := leaseRecord{address: address, generation: generation}
	p.byClient[clientID] = record
	p.byAddr[address] = clientID
	return nil
}

func (p *Pool) persistStateLocked() error {
	if p.statePath == "" {
		return nil
	}
	state := poolState{Version: 2, Leases: make(map[string]persistedLease, len(p.byClient))}
	for clientID, record := range p.byClient {
		state.Leases[clientID] = persistedLease{
			Address:    record.address.String(),
			Generation: record.generation,
		}
	}
	data, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("encode lease state: %w", err)
	}
	data = append(data, '\n')
	if err := os.MkdirAll(filepath.Dir(p.statePath), 0o700); err != nil {
		return fmt.Errorf("create lease state directory: %w", err)
	}
	temp, err := os.CreateTemp(filepath.Dir(p.statePath), ".leases-*")
	if err != nil {
		return fmt.Errorf("create lease state temporary file: %w", err)
	}
	tempName := temp.Name()
	defer os.Remove(tempName)
	if err := temp.Chmod(0o600); err != nil {
		_ = temp.Close()
		return fmt.Errorf("secure lease state temporary file: %w", err)
	}
	if _, err := temp.Write(data); err != nil {
		_ = temp.Close()
		return fmt.Errorf("write lease state: %w", err)
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return fmt.Errorf("sync lease state: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close lease state: %w", err)
	}
	if err := os.Rename(tempName, p.statePath); err != nil {
		return fmt.Errorf("replace lease state: %w", err)
	}
	if runtime.GOOS != "windows" {
		directory, err := os.Open(filepath.Dir(p.statePath))
		if err != nil {
			return fmt.Errorf("open lease state directory: %w", err)
		}
		if err := directory.Sync(); err != nil {
			_ = directory.Close()
			return fmt.Errorf("sync lease state directory: %w", err)
		}
		if err := directory.Close(); err != nil {
			return fmt.Errorf("close lease state directory: %w", err)
		}
	}
	return nil
}

func (p *Pool) lease(clientID string, record leaseRecord) Lease {
	return Lease{
		Address:    record.address,
		PrefixBits: p.prefix.Bits(),
		Gateway:    p.gateway,
		generation: record.generation,
		clientID:   clientID,
	}
}

func lastAddress(prefix netip.Prefix) netip.Addr {
	base := prefix.Addr().As4()
	hostBits := 32 - prefix.Bits()
	value := uint32(base[0])<<24 | uint32(base[1])<<16 | uint32(base[2])<<8 | uint32(base[3])
	value |= uint32(1<<hostBits) - 1
	return netip.AddrFrom4([4]byte{byte(value >> 24), byte(value >> 16), byte(value >> 8), byte(value)})
}
