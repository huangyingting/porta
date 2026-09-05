package forwardproxy

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

type cachedAddresses struct {
	addresses []netip.Addr
	expires   time.Time
}

type addressCache struct {
	mu         sync.Mutex
	entries    map[string]cachedAddresses
	maxEntries int
	ttl        time.Duration
}

func newAddressCache(maxEntries int, ttl time.Duration) *addressCache {
	return &addressCache{
		entries:    make(map[string]cachedAddresses),
		maxEntries: maxEntries,
		ttl:        ttl,
	}
}

func (c *addressCache) Get(host string, now time.Time) ([]netip.Addr, bool) {
	if c == nil || c.maxEntries <= 0 || c.ttl <= 0 {
		return nil, false
	}
	key := normalizeCacheHost(host)
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
	if !ok {
		return nil, false
	}
	if !now.Before(entry.expires) {
		delete(c.entries, key)
		return nil, false
	}
	return append([]netip.Addr(nil), entry.addresses...), true
}

func (c *addressCache) Put(host string, addresses []netip.Addr, now time.Time) {
	if c == nil || c.maxEntries <= 0 || c.ttl <= 0 || len(addresses) == 0 {
		return
	}
	key := normalizeCacheHost(host)
	c.mu.Lock()
	defer c.mu.Unlock()
	for cachedHost, entry := range c.entries {
		if !now.Before(entry.expires) {
			delete(c.entries, cachedHost)
		}
	}
	if _, exists := c.entries[key]; !exists && len(c.entries) >= c.maxEntries {
		var oldestHost string
		var oldestExpiry time.Time
		for cachedHost, entry := range c.entries {
			if oldestHost == "" || entry.expires.Before(oldestExpiry) {
				oldestHost = cachedHost
				oldestExpiry = entry.expires
			}
		}
		delete(c.entries, oldestHost)
	}
	c.entries[key] = cachedAddresses{
		addresses: append([]netip.Addr(nil), addresses...),
		expires:   now.Add(c.ttl),
	}
}

func normalizeCacheHost(host string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
}

type dialResult struct {
	connection net.Conn
	err        error
}

func dialHappyEyeballs(
	ctx context.Context,
	dial func(context.Context, string, string) (net.Conn, error),
	network string,
	port string,
	addresses []netip.Addr,
	delay time.Duration,
) (net.Conn, error) {
	ordered := interleaveAddressFamilies(addresses)
	if len(ordered) == 0 {
		return nil, errors.New("destination has no addresses")
	}
	if delay < 0 {
		delay = 0
	}
	dialCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan dialResult, len(ordered))
	startAttempt := func(address netip.Addr) {
		go func() {
			connection, err := dial(dialCtx, network, net.JoinHostPort(address.String(), port))
			if err == nil {
				results <- dialResult{connection: connection}
				return
			}
			results <- dialResult{err: err}
		}()
	}

	next := 0
	active := 0
	startNext := func() {
		startAttempt(ordered[next])
		next++
		active++
	}
	startNext()

	var timer *time.Timer
	var timerC <-chan time.Time
	resetTimer := func() {
		if next >= len(ordered) || delay == 0 {
			timerC = nil
			return
		}
		if timer == nil {
			timer = time.NewTimer(delay)
		} else {
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(delay)
		}
		timerC = timer.C
	}
	if delay == 0 {
		for next < len(ordered) {
			startNext()
		}
	} else {
		resetTimer()
	}
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()

	var lastErr error
	for active > 0 {
		select {
		case result := <-results:
			active--
			if result.connection != nil {
				cancel()
				go closeLateDialResults(results, active)
				return result.connection, nil
			}
			if result.err != nil && !errors.Is(result.err, context.Canceled) {
				lastErr = result.err
			}
			if next < len(ordered) {
				startNext()
				resetTimer()
			}
		case <-timerC:
			timerC = nil
			if next < len(ordered) {
				startNext()
				resetTimer()
			}
		case <-ctx.Done():
			cancel()
			go closeLateDialResults(results, active)
			return nil, ctx.Err()
		}
	}
	if lastErr == nil {
		lastErr = errors.New("destination has no reachable addresses")
	}
	return nil, lastErr
}

func closeLateDialResults(results <-chan dialResult, remaining int) {
	for range remaining {
		result := <-results
		if result.connection != nil {
			_ = result.connection.Close()
		}
	}
}

func interleaveAddressFamilies(addresses []netip.Addr) []netip.Addr {
	if len(addresses) < 2 {
		return append([]netip.Addr(nil), addresses...)
	}
	firstIsIPv6 := addresses[0].Is6()
	ipv4 := make([]netip.Addr, 0, len(addresses))
	ipv6 := make([]netip.Addr, 0, len(addresses))
	for _, address := range addresses {
		if address.Is6() {
			ipv6 = append(ipv6, address)
		} else {
			ipv4 = append(ipv4, address)
		}
	}
	first, second := ipv4, ipv6
	if firstIsIPv6 {
		first, second = ipv6, ipv4
	}
	result := make([]netip.Addr, 0, len(addresses))
	for index := 0; index < max(len(first), len(second)); index++ {
		if index < len(first) {
			result = append(result, first[index])
		}
		if index < len(second) {
			result = append(result, second[index])
		}
	}
	return result
}
