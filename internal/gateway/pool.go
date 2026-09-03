package gateway

import (
	"errors"
	"fmt"
	"net/netip"
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
}

type Pool struct {
	mu       sync.Mutex
	prefix   netip.Prefix
	gateway  netip.Addr
	byClient map[string]leaseRecord
	byAddr   map[netip.Addr]string
	nextGen  uint64
}

func NewPool(cidr string) (*Pool, error) {
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
	return &Pool{
		prefix:   prefix,
		gateway:  gateway,
		byClient: make(map[string]leaseRecord),
		byAddr:   make(map[netip.Addr]string),
	}, nil
}

func (p *Pool) Acquire(clientID string) (Lease, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.nextGen++
	if existing, ok := p.byClient[clientID]; ok {
		existing.generation = p.nextGen
		p.byClient[clientID] = existing
		return p.lease(clientID, existing), nil
	}

	last := lastAddress(p.prefix)
	for candidate := p.gateway.Next(); candidate.IsValid() && candidate.Compare(last) < 0; candidate = candidate.Next() {
		if _, inUse := p.byAddr[candidate]; inUse {
			continue
		}
		record := leaseRecord{address: candidate, generation: p.nextGen}
		p.byClient[clientID] = record
		p.byAddr[candidate] = clientID
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
	delete(p.byClient, lease.clientID)
	delete(p.byAddr, record.address)
}

func (p *Pool) Gateway() netip.Addr { return p.gateway }

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
