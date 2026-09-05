package forwardproxy

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestDialHappyEyeballsStartsAlternateAddressFamily(t *testing.T) {
	addresses := []netip.Addr{
		netip.MustParseAddr("2001:4860:4860::8888"),
		netip.MustParseAddr("2001:4860:4860::8844"),
		netip.MustParseAddr("1.1.1.1"),
	}
	var callsMu sync.Mutex
	var calls []string
	var peer net.Conn
	dial := func(ctx context.Context, _, address string) (net.Conn, error) {
		callsMu.Lock()
		calls = append(calls, address)
		callsMu.Unlock()
		if address == "1.1.1.1:443" {
			client, server := net.Pipe()
			peer = server
			return client, nil
		}
		<-ctx.Done()
		return nil, ctx.Err()
	}
	started := time.Now()
	connection, err := dialHappyEyeballs(
		context.Background(),
		dial,
		"tcp",
		"443",
		addresses,
		10*time.Millisecond,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	defer peer.Close()
	if elapsed := time.Since(started); elapsed >= 100*time.Millisecond {
		t.Fatalf("alternate family dial took %s", elapsed)
	}
	callsMu.Lock()
	defer callsMu.Unlock()
	if len(calls) < 2 || calls[0] != "[2001:4860:4860::8888]:443" || calls[1] != "1.1.1.1:443" {
		t.Fatalf("dial order = %v", calls)
	}
}

func TestDialHappyEyeballsAcceleratesAfterImmediateFailure(t *testing.T) {
	first := netip.MustParseAddr("2001:db8::1")
	second := netip.MustParseAddr("192.0.2.1")
	secondStarted := make(chan struct{})
	dial := func(_ context.Context, _, address string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		if host == first.String() {
			return nil, errors.New("unreachable")
		}
		close(secondStarted)
		connection, peer := net.Pipe()
		_ = peer.Close()
		return connection, nil
	}
	connection, err := dialHappyEyeballs(
		context.Background(),
		dial,
		"tcp",
		"443",
		[]netip.Addr{first, second},
		500*time.Millisecond,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	select {
	case <-secondStarted:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("alternate-family attempt waited for the full stagger after an immediate failure")
	}
}

func TestDialHappyEyeballsClosesConcurrentLateSuccess(t *testing.T) {
	addresses := []netip.Addr{
		netip.MustParseAddr("2001:4860:4860::8888"),
		netip.MustParseAddr("1.1.1.1"),
	}
	var connectionsMu sync.Mutex
	var connections []*closeTrackingConn
	var peers []net.Conn
	bothStarted := make(chan struct{})
	dial := func(context.Context, string, string) (net.Conn, error) {
		client, peer := net.Pipe()
		connection := &closeTrackingConn{Conn: client, closed: make(chan struct{})}
		connectionsMu.Lock()
		connections = append(connections, connection)
		peers = append(peers, peer)
		if len(connections) == len(addresses) {
			close(bothStarted)
		}
		connectionsMu.Unlock()
		<-bothStarted
		return connection, nil
	}
	winner, err := dialHappyEyeballs(context.Background(), dial, "tcp", "443", addresses, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer winner.Close()
	connectionsMu.Lock()
	created := append([]*closeTrackingConn(nil), connections...)
	createdPeers := append([]net.Conn(nil), peers...)
	connectionsMu.Unlock()
	defer func() {
		for _, peer := range createdPeers {
			_ = peer.Close()
		}
	}()
	for _, connection := range created {
		if connection == winner {
			continue
		}
		select {
		case <-connection.closed:
		case <-time.After(time.Second):
			t.Fatal("late successful connection was not closed")
		}
	}
}

func TestAddressCacheExpiresAndReturnsCopies(t *testing.T) {
	cache := newAddressCache(2, time.Minute)
	now := time.Unix(100, 0)
	addresses := []netip.Addr{netip.MustParseAddr("1.1.1.1")}
	cache.Put("Example.COM.", addresses, now)
	addresses[0] = netip.MustParseAddr("8.8.8.8")

	got, ok := cache.Get("example.com", now.Add(time.Second))
	if !ok || len(got) != 1 || got[0] != netip.MustParseAddr("1.1.1.1") {
		t.Fatalf("cache result = %v, %t", got, ok)
	}

	got[0] = netip.MustParseAddr("9.9.9.9")
	got, _ = cache.Get("example.com", now.Add(time.Second))
	if got[0] != netip.MustParseAddr("1.1.1.1") {
		t.Fatal("caller mutated cached addresses")
	}
	if _, ok := cache.Get("example.com", now.Add(time.Minute)); ok {
		t.Fatal("expired cache entry remained available")
	}
}

func TestDialPublicCachesOnlyValidatedAddresses(t *testing.T) {
	var resolves atomic.Int32
	now := time.Unix(200, 0)
	handler := &Handler{
		resolve: func(context.Context, string) ([]netip.Addr, error) {
			resolves.Add(1)
			return []netip.Addr{netip.MustParseAddr("1.1.1.1")}, nil
		},
		dialAddress: func(context.Context, string, string) (net.Conn, error) {
			client, peer := net.Pipe()
			_ = peer.Close()
			return client, nil
		},
		dnsCache: newAddressCache(4, time.Minute),
		now:      func() time.Time { return now },
	}
	for range 2 {
		connection, err := handler.dialPublic(context.Background(), "tcp", "example.com:443")
		if err != nil {
			t.Fatal(err)
		}
		_ = connection.Close()
	}
	if resolves.Load() != 1 {
		t.Fatalf("DNS resolutions = %d, want 1", resolves.Load())
	}

	handler.resolve = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{
			netip.MustParseAddr("1.1.1.1"),
			netip.MustParseAddr("127.0.0.1"),
		}, nil
	}
	if _, err := handler.dialPublic(context.Background(), "tcp", "mixed.example:443"); !errors.Is(err, errDestinationDenied) {
		t.Fatalf("mixed public/private result error = %v", err)
	}
	if _, ok := handler.dnsCache.Get("mixed.example", now); ok {
		t.Fatal("denied DNS result entered cache")
	}
}

type closeTrackingConn struct {
	net.Conn
	once   sync.Once
	closed chan struct{}
}

func (c *closeTrackingConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.Conn.Close()
}
