package abuse

import (
	"errors"
	"net/netip"
	"sync"
	"time"
)

type Surface uint8

const (
	NativeAuthentication Surface = iota
	ProxyAuthentication
	PortalAuthentication
	InvitationRedemption
	surfaceCount
)

const overflowShards = 64

func (surface Surface) String() string {
	switch surface {
	case NativeAuthentication:
		return "native"
	case ProxyAuthentication:
		return "proxy"
	case PortalAuthentication:
		return "portal"
	case InvitationRedemption:
		return "invitation"
	default:
		return "unknown"
	}
}

type Policy struct {
	Burst          int
	RefillInterval time.Duration
}

type entryKey struct {
	surface Surface
	address netip.Addr
}

type bucket struct {
	tokens   float64
	updated  time.Time
	lastSeen time.Time
}

type Guard struct {
	mu         sync.Mutex
	policies   [surfaceCount]Policy
	entries    map[entryKey]*bucket
	overflow   [surfaceCount][overflowShards]bucket
	maxEntries int
	idleExpiry time.Duration
	nextPrune  time.Time
	now        func() time.Time
	onReject   func(Surface)
}

func NewDefault(onReject func(Surface)) *Guard {
	guard, err := New(
		map[Surface]Policy{
			NativeAuthentication: {Burst: 32, RefillInterval: 2 * time.Second},
			ProxyAuthentication:  {Burst: 32, RefillInterval: 5 * time.Second},
			PortalAuthentication: {Burst: 12, RefillInterval: 10 * time.Second},
			InvitationRedemption: {Burst: 12, RefillInterval: 10 * time.Second},
		},
		4096,
		15*time.Minute,
		time.Now,
		onReject,
	)
	if err != nil {
		panic(err)
	}
	return guard
}

func New(
	policies map[Surface]Policy,
	maxEntries int,
	idleExpiry time.Duration,
	now func() time.Time,
	onReject func(Surface),
) (*Guard, error) {
	if maxEntries <= 0 || idleExpiry <= 0 || now == nil {
		return nil, errors.New("invalid abuse guard bounds")
	}
	guard := &Guard{
		entries:    make(map[entryKey]*bucket, maxEntries),
		maxEntries: maxEntries,
		idleExpiry: idleExpiry,
		now:        now,
		onReject:   onReject,
	}
	for surface := Surface(0); surface < surfaceCount; surface++ {
		policy, ok := policies[surface]
		if !ok || policy.Burst <= 0 || policy.RefillInterval <= 0 {
			return nil, errors.New("missing or invalid abuse guard policy")
		}
		guard.policies[surface] = policy
	}
	return guard, nil
}

func (guard *Guard) Reserve(surface Surface, address netip.Addr) (func(), bool) {
	if guard == nil {
		return func() {}, true
	}
	if surface >= surfaceCount {
		return nil, false
	}
	address = address.Unmap()
	now := guard.now()
	guard.mu.Lock()
	target := guard.bucketLocked(surface, address, now)
	policy := guard.policies[surface]
	refill(target, policy, now)
	target.lastSeen = now
	if target.tokens < 1 {
		guard.mu.Unlock()
		if guard.onReject != nil {
			guard.onReject(surface)
		}
		return nil, false
	}
	target.tokens--
	guard.mu.Unlock()

	var once sync.Once
	return func() {
		once.Do(func() {
			now := guard.now()
			guard.mu.Lock()
			refill(target, policy, now)
			target.tokens = min(float64(policy.Burst), target.tokens+1)
			target.lastSeen = now
			guard.mu.Unlock()
		})
	}, true
}

func (guard *Guard) bucketLocked(surface Surface, address netip.Addr, now time.Time) *bucket {
	key := entryKey{surface: surface, address: address}
	if target := guard.entries[key]; target != nil {
		return target
	}
	if len(guard.entries) >= guard.maxEntries && !now.Before(guard.nextPrune) {
		for existing, target := range guard.entries {
			if now.Sub(target.lastSeen) >= guard.idleExpiry {
				delete(guard.entries, existing)
			}
		}
		guard.nextPrune = now.Add(min(guard.idleExpiry, time.Minute))
	}
	if address.IsValid() && len(guard.entries) < guard.maxEntries {
		target := &bucket{tokens: float64(guard.policies[surface].Burst), updated: now, lastSeen: now}
		guard.entries[key] = target
		return target
	}
	index := addressShard(address)
	target := &guard.overflow[surface][index]
	if target.updated.IsZero() {
		target.tokens = float64(guard.policies[surface].Burst)
		target.updated = now
	}
	return target
}

func refill(target *bucket, policy Policy, now time.Time) {
	if target.updated.IsZero() {
		target.tokens = float64(policy.Burst)
		target.updated = now
		return
	}
	if now.After(target.updated) {
		target.tokens = min(
			float64(policy.Burst),
			target.tokens+float64(now.Sub(target.updated))/float64(policy.RefillInterval),
		)
		target.updated = now
	}
}

func addressShard(address netip.Addr) int {
	if !address.IsValid() {
		return 0
	}
	bytes := address.As16()
	hash := uint32(2166136261)
	for _, value := range bytes {
		hash ^= uint32(value)
		hash *= 16777619
	}
	return int(hash % overflowShards)
}
