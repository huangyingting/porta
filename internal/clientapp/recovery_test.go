package clientapp

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/huangyingting/porta/internal/clientid"
	"github.com/huangyingting/porta/internal/device"
	"github.com/huangyingting/porta/internal/protocol"
	"github.com/huangyingting/porta/internal/tunnel"
	"github.com/quic-go/quic-go"
)

func TestAutomaticTransportPolicy(t *testing.T) {
	unavailable := tunnel.TransportUnavailableError{Err: context.DeadlineExceeded}
	for _, test := range []struct {
		name      string
		transport tunnel.Transport
		err       error
		want      []tunnel.Transport
	}{
		{"default", "", unavailable, []tunnel.Transport{tunnel.TransportHTTP3, tunnel.TransportHTTP2}},
		{"automatic", tunnel.TransportAuto, unavailable, []tunnel.Transport{tunnel.TransportHTTP3, tunnel.TransportHTTP2}},
		{"explicit h3", tunnel.TransportHTTP3, unavailable, []tunnel.Transport{tunnel.TransportHTTP3}},
		{"explicit h2", tunnel.TransportHTTP2, unavailable, []tunnel.Transport{tunnel.TransportHTTP2}},
		{"certificate", tunnel.TransportAuto, x509.UnknownAuthorityError{}, []tunnel.Transport{tunnel.TransportHTTP3}},
		{"wrapped certificate", tunnel.TransportAuto, tunnel.TransportUnavailableError{Err: x509.UnknownAuthorityError{}}, []tunnel.Transport{tunnel.TransportHTTP3}},
		{"TLS record", tunnel.TransportAuto, tunnel.TransportUnavailableError{Err: tls.RecordHeaderError{}}, []tunnel.Transport{tunnel.TransportHTTP3}},
		{"TLS alert", tunnel.TransportAuto, tunnel.TransportUnavailableError{Err: tls.AlertError(40)}, []tunnel.Transport{tunnel.TransportHTTP3}},
		{"QUIC crypto", tunnel.TransportAuto, tunnel.TransportUnavailableError{Err: &quic.TransportError{ErrorCode: 0x128}}, []tunnel.Transport{tunnel.TransportHTTP3}},
		{"QUIC protocol", tunnel.TransportAuto, tunnel.TransportUnavailableError{Err: &quic.TransportError{ErrorCode: 0xa}}, []tunnel.Transport{tunnel.TransportHTTP3}},
		{"authorization", tunnel.TransportAuto, tunnel.PermanentError{Err: errors.New("unauthorized")}, []tunnel.Transport{tunnel.TransportHTTP3}},
		{"permanent timeout", tunnel.TransportAuto, tunnel.PermanentError{Err: context.DeadlineExceeded}, []tunnel.Transport{tunnel.TransportHTTP3}},
		{"protocol", tunnel.TransportAuto, errors.New("invalid CONNECT-IP response"), []tunnel.Transport{tunnel.TransportHTTP3}},
		{"unclassified timeout", tunnel.TransportAuto, context.DeadlineExceeded, []tunnel.Transport{tunnel.TransportHTTP3}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var calls []tunnel.Transport
			connection, err := dialAutomatic(context.Background(), tunnel.Config{Transport: test.transport}, func(_ context.Context, config tunnel.Config) (*clientConnection, error) {
				calls = append(calls, config.Transport)
				if len(calls) == 1 {
					return nil, test.err
				}
				return &clientConnection{}, nil
			})
			if !reflect.DeepEqual(calls, test.want) {
				t.Fatalf("attempts %v, want %v", calls, test.want)
			}
			if len(calls) == 2 && (err != nil || connection.transport != tunnel.TransportHTTP2) {
				t.Fatalf("fallback connection=%+v error=%v", connection, err)
			}
		})
	}
}

func TestInitialTransientRetriesAndReportsActualTransport(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	calls := 0
	identityCalls := 0
	resolveIdentity := func() (*clientid.Identity, error) {
		identityCalls++
		return testIdentity()
	}
	connected := false
	err := run(ctx, resolveIdentity, Config{ServerURL: "https://192.0.2.1", Token: "token", Reconnect: true}, func(event Event) {
		if event.State == StateConnected {
			connected = true
			if event.Transport != tunnel.TransportHTTP2 {
				t.Errorf("reported transport %q", event.Transport)
			}
			cancel()
		}
	}, func(_ context.Context, config tunnel.Config) (*clientConnection, error) {
		calls++
		proof, proofErr := config.DeviceProof(http.MethodConnect, protocol.MasquePath)
		if want, _ := testIdentity(); proofErr != nil || proof.DeviceID != want.ID || proof.Name != want.Name {
			t.Fatalf("retry or fallback lost device identity: proof=%#v error=%v", proof, proofErr)
		}
		if calls <= 2 || config.Transport == tunnel.TransportHTTP3 {
			return nil, tunnel.TransportUnavailableError{Err: context.DeadlineExceeded}
		}
		return &clientConnection{packetConnection: &testConnection{closed: make(chan struct{})}, lease: tunnel.Lease{MTU: 1280}}, nil
	}, func(string, int) (device.PacketDevice, error) {
		return &testDevice{readStarted: make(chan struct{})}, nil
	})
	if !connected || calls != 4 || identityCalls != 1 || !errors.Is(err, context.Canceled) {
		t.Fatalf("connected=%t attempts=%d identity lookups=%d error=%v", connected, calls, identityCalls, err)
	}
}

func TestUnavailableIdentityDoesNotDialOrChangeNetworking(t *testing.T) {
	missing := errors.New("machine name unavailable")
	network := &recoveryNetwork{}
	err := run(context.Background(), func() (*clientid.Identity, error) { return nil, missing },
		Config{ServerURL: "https://192.0.2.1", Token: "token", Network: network}, nil,
		func(context.Context, tunnel.Config) (*clientConnection, error) {
			t.Fatal("dialed without a machine-name identity")
			return nil, nil
		}, func(string, int) (device.PacketDevice, error) {
			t.Fatal("opened a device without a machine-name identity")
			return nil, nil
		})
	if !errors.Is(err, missing) || network.guard || network.prepared != 0 || network.up != 0 || network.down != 0 {
		t.Fatalf("identity failure was swallowed or changed networking: %v, %+v", err, network)
	}
}

func TestPermanentStartupFailsWithoutRetry(t *testing.T) {
	for _, failure := range []error{
		errors.New("invalid lease"),
		tunnel.PermanentError{Err: context.DeadlineExceeded},
		x509.UnknownAuthorityError{},
	} {
		calls := 0
		err := run(context.Background(), testIdentity, Config{ServerURL: "https://gateway.example", Token: "token", Reconnect: true}, nil,
			func(context.Context, tunnel.Config) (*clientConnection, error) {
				calls++
				return nil, failure
			}, func(string, int) (device.PacketDevice, error) {
				t.Fatal("opened device after failed handshake")
				return nil, nil
			})
		if calls != 1 || !errors.Is(err, failure) {
			t.Fatalf("calls=%d error=%v, want %v", calls, err, failure)
		}
	}
}

type recoveryNetwork struct {
	guard        bool
	prepared     int
	up           int
	reconfigured int
	down         int
	reconfigure  func(tunnel.Lease) error
}

func (n *recoveryNetwork) Prepare(_ context.Context, remote net.Addr) error {
	if remote.String() != "192.0.2.1:443" {
		return errors.New("unexpected physical endpoint")
	}
	n.guard = true
	n.prepared++
	return nil
}
func (n *recoveryNetwork) Up(context.Context, string, net.Addr, tunnel.Lease) error {
	if !n.guard {
		return errors.New("configured without guard")
	}
	n.up++
	return nil
}
func (n *recoveryNetwork) Reconfigure(_ context.Context, _ string, _ net.Addr, lease tunnel.Lease) error {
	if !n.guard {
		return errors.New("reconfigured without guard")
	}
	n.reconfigured++
	if n.reconfigure != nil {
		return n.reconfigure(lease)
	}
	return nil
}
func (n *recoveryNetwork) Down(context.Context) error {
	n.guard = false
	n.down++
	return nil
}

type packetQueueDevice struct {
	packets chan []byte
	started chan struct{}
	once    sync.Once
	exited  atomic.Bool
	closed  atomic.Bool
	reading atomic.Int32
}

func (d *packetQueueDevice) ReadPacket(ctx context.Context) ([]byte, error) {
	d.reading.Add(1)
	defer d.reading.Add(-1)
	d.once.Do(func() { close(d.started) })
	select {
	case packet := <-d.packets:
		return packet, nil
	case <-ctx.Done():
		d.exited.Store(true)
		return nil, ctx.Err()
	}
}
func (*packetQueueDevice) WritePacket(context.Context, []byte) error { return nil }
func (*packetQueueDevice) Name() string                              { return "porta-test" }
func (d *packetQueueDevice) Close() error                            { d.closed.Store(true); return nil }

func TestReconnectReplacesLeaseMTUDNSAndDrainsOldPackets(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	network := &recoveryNetwork{}
	oldDevice := &packetQueueDevice{packets: make(chan []byte, 300), started: make(chan struct{})}
	newDevice := &packetQueueDevice{packets: make(chan []byte), started: make(chan struct{})}
	oldLease := tunnel.Lease{Address: netip.MustParsePrefix("10.0.0.2/32"), DNS: netip.MustParseAddr("10.0.0.1"), MTU: 1280}
	newLease := tunnel.Lease{Address: netip.MustParsePrefix("10.1.0.2/32"), DNS: netip.MustParseAddr("10.1.0.1"), MTU: 1400}
	attempts, opens, connected := 0, 0, 0
	var stalePackets atomic.Int32
	first := &testConnection{closed: make(chan struct{})}
	first.receive = func() ([]byte, error) {
		<-oldDevice.started
		return nil, io.EOF
	}
	second := &testConnection{closed: make(chan struct{})}
	second.send = func([]byte) error { stalePackets.Add(1); return nil }
	network.reconfigure = func(lease tunnel.Lease) error {
		if !oldDevice.closed.Load() || oldDevice.reading.Load() != 0 || lease != newLease {
			t.Error("reconfiguration did not replace old reader/device/lease")
		}
		return nil
	}
	err := run(ctx, testIdentity, Config{ServerURL: "https://192.0.2.1", Token: "token", Reconnect: true, Network: network}, func(event Event) {
		if event.State == StateReconnecting {
			if !network.guard || network.down != 0 {
				t.Error("guard removed during reconnect")
			}
			packet := make([]byte, 20)
			packet[0], packet[3], packet[12] = 0x45, 20, 10
			for range 300 {
				oldDevice.packets <- packet
			}
		}
		if event.State == StateConnected {
			connected++
			if connected == 2 && event.Lease != newLease {
				t.Error("connected event retained stale lease")
			}
			if connected == 3 {
				cancel()
			}
		}
	}, func(_ context.Context, config tunnel.Config) (*clientConnection, error) {
		attempts++
		if config.DialAddress != "192.0.2.1:443" {
			t.Error("dial did not use pinned endpoint")
		}
		if attempts == 1 {
			if network.guard || network.prepared != 0 {
				t.Error("claimed protection before bootstrap handshake")
			}
		} else if !network.guard || network.prepared != attempts {
			t.Error("reconnect dial happened without preparing pinned endpoint")
		}
		lease, packets := oldLease, first
		if attempts == 2 {
			lease, packets = newLease, second
		}
		return &clientConnection{packetConnection: packets, lease: lease, remoteAddr: &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 443}}, nil
	}, func(_ string, mtu int) (device.PacketDevice, error) {
		opens++
		if opens == 1 {
			return oldDevice, nil
		}
		if mtu != newLease.MTU || !oldDevice.closed.Load() || oldDevice.reading.Load() != 0 {
			t.Error("new TUN opened before old TUN/reader stopped or with wrong MTU")
		}
		return newDevice, nil
	})
	if !errors.Is(err, context.Canceled) || opens != 2 || attempts != 2 || network.up != 1 || network.reconfigured != 1 || network.down != 1 || network.guard {
		t.Fatalf("error=%v opens=%d attempts=%d network=%+v", err, opens, attempts, network)
	}
	if stalePackets.Load() != 0 || !newDevice.closed.Load() || !newDevice.exited.Load() {
		t.Fatalf("stale packets=%d new reader exited=%t closed=%t", stalePackets.Load(), newDevice.exited.Load(), newDevice.closed.Load())
	}
}

func TestTerminalFailureRetainsPreparedGuardUntilExplicitCleanup(t *testing.T) {
	network := &recoveryNetwork{}
	failure := tunnel.PermanentError{Err: errors.New("authorization rejected")}
	tunDevice := &testDevice{readStarted: make(chan struct{})}
	connection := &testConnection{closed: make(chan struct{})}
	connection.receive = func() ([]byte, error) {
		<-tunDevice.readStarted
		return nil, failure
	}
	err := run(context.Background(), testIdentity, Config{ServerURL: "https://192.0.2.1", Token: "token", Network: network, Reconnect: true}, nil,
		func(context.Context, tunnel.Config) (*clientConnection, error) {
			return &clientConnection{packetConnection: connection, lease: tunnel.Lease{MTU: 1280}}, nil
		}, func(string, int) (device.PacketDevice, error) { return tunDevice, nil })
	if !errors.Is(err, failure) || !network.guard || network.down != 0 {
		t.Fatalf("terminal error released guard: error=%v network=%+v", err, network)
	}
	if err := network.Down(context.Background()); err != nil || network.guard {
		t.Fatalf("explicit recovery failed: %v", err)
	}
}

type namedRecoveryNetwork struct {
	*recoveryNetwork
	interfaceName string
}

func (n *namedRecoveryNetwork) Prepare(ctx context.Context, name string, endpoint net.Addr) error {
	n.interfaceName = name
	return n.recoveryNetwork.Prepare(ctx, endpoint)
}

func TestNamedPrepareAfterBootstrapAndCanceledSessionCleanup(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	network := &namedRecoveryNetwork{recoveryNetwork: &recoveryNetwork{}}
	err := run(ctx, testIdentity, Config{ServerURL: "https://192.0.2.1", Token: "token", InterfaceName: "Porta-owned", Network: network}, func(event Event) {
		if event.State == StateConnected {
			if !network.guard || network.interfaceName != "Porta-owned" {
				t.Error("named guard not prepared before connection became usable")
			}
			cancel()
		}
	},
		func(context.Context, tunnel.Config) (*clientConnection, error) {
			if network.guard {
				t.Error("guard unexpectedly active during initial bootstrap")
			}
			return &clientConnection{packetConnection: &testConnection{closed: make(chan struct{})}, lease: tunnel.Lease{MTU: 1280}}, nil
		}, func(string, int) (device.PacketDevice, error) {
			return &testDevice{readStarted: make(chan struct{})}, nil
		})
	if !errors.Is(err, context.Canceled) || network.guard || network.down != 1 {
		t.Fatalf("canceled startup retained guard: error=%v network=%+v", err, network)
	}
}

func TestReconnectPermanentFailureStopsPromptly(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	failure := tunnel.PermanentError{Err: errors.New("revoked")}
	tunDevice := &testDevice{readStarted: make(chan struct{})}
	connection := &testConnection{closed: make(chan struct{})}
	connection.receive = func() ([]byte, error) {
		<-tunDevice.readStarted
		return nil, io.EOF
	}
	attempts := 0
	err := run(ctx, testIdentity, Config{ServerURL: "https://192.0.2.1", Token: "token", Reconnect: true}, nil,
		func(context.Context, tunnel.Config) (*clientConnection, error) {
			attempts++
			if attempts > 1 {
				return nil, failure
			}
			return &clientConnection{packetConnection: connection, lease: tunnel.Lease{MTU: 1280}}, nil
		}, func(string, int) (device.PacketDevice, error) { return tunDevice, nil })
	if !errors.Is(err, failure) || attempts != 2 || !tunDevice.closed.Load() || !tunDevice.readExited.Load() {
		t.Fatalf("error=%v attempts=%d closed=%t readerExited=%t", err, attempts, tunDevice.closed.Load(), tunDevice.readExited.Load())
	}
}

func TestResolveNumericEndpoints(t *testing.T) {
	for _, test := range []struct{ origin, want string }{
		{"https://192.0.2.1", "192.0.2.1:443"},
		{"https://10.20.30.40", "10.20.30.40:443"},
		{"https://[2001:db8::1]:8443", "[2001:db8::1]:8443"},
		{"https://[fd00::1]", "[fd00::1]:443"},
	} {
		endpoint, err := url.Parse(test.origin)
		if err != nil {
			t.Fatal(err)
		}
		resolved, err := resolveEndpoints(context.Background(), endpoint)
		if err != nil || len(resolved) != 1 || resolved[0].String() != test.want {
			t.Fatalf("resolve %s = %v, %v", test.origin, resolved, err)
		}
	}
}

type transportRecoveryNetwork struct {
	*recoveryNetwork
	protocols []string
}

func (n *transportRecoveryNetwork) Prepare(ctx context.Context, endpoint net.Addr) error {
	n.protocols = append(n.protocols, endpoint.Network())
	return n.recoveryNetwork.Prepare(ctx, endpoint)
}

func TestProtectedFallbackPreparesEachTransportBeforeDial(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	network := &transportRecoveryNetwork{recoveryNetwork: &recoveryNetwork{}}
	tunDevice := &testDevice{readStarted: make(chan struct{})}
	first := &testConnection{closed: make(chan struct{})}
	first.receive = func() ([]byte, error) {
		<-tunDevice.readStarted
		return nil, io.EOF
	}
	second := &testConnection{closed: make(chan struct{})}
	attempts, connected := 0, 0
	err := run(ctx, testIdentity, Config{ServerURL: "https://192.0.2.1", Token: "token", Reconnect: true, Network: network}, func(event Event) {
		if event.State == StateConnected {
			connected++
			if connected == 2 {
				if event.Transport != tunnel.TransportHTTP2 {
					t.Errorf("fallback transport = %q", event.Transport)
				}
				cancel()
			}
		}
	}, func(_ context.Context, config tunnel.Config) (*clientConnection, error) {
		attempts++
		packets := first
		if attempts > 1 {
			want := "udp"
			if config.Transport == tunnel.TransportHTTP2 {
				want = "tcp"
			}
			if got := network.protocols[len(network.protocols)-1]; got != want {
				t.Fatalf("prepared %s before %s transport dial", got, config.Transport)
			}
			if config.Transport == tunnel.TransportHTTP3 {
				return nil, tunnel.TransportUnavailableError{Err: context.DeadlineExceeded}
			}
			packets = second
		}
		return &clientConnection{
			packetConnection: packets, lease: tunnel.Lease{MTU: 1280},
			remoteAddr: &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 443},
		}, nil
	}, func(string, int) (device.PacketDevice, error) { return tunDevice, nil })
	if !errors.Is(err, context.Canceled) || !reflect.DeepEqual(network.protocols, []string{"udp", "udp", "tcp"}) {
		t.Fatalf("error=%v prepared protocols=%v", err, network.protocols)
	}
}

type journalRecoveryNetwork struct {
	*recoveryNetwork
	endpoints []net.Addr
}

func (n *journalRecoveryNetwork) RecoveryEndpoints() []net.Addr {
	return append([]net.Addr(nil), n.endpoints...)
}

func denyPhysicalDNS(t *testing.T) *atomic.Int32 {
	t.Helper()
	previousResolver := net.DefaultResolver
	lookups := new(atomic.Int32)
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		lookups.Add(1)
		return nil, errors.New("physical DNS forbidden")
	}}
	t.Cleanup(func() { net.DefaultResolver = previousResolver })
	return lookups
}

func TestCrashRecoveryUsesJournalWithoutPhysicalDNS(t *testing.T) {
	lookups := denyPhysicalDNS(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	network := &journalRecoveryNetwork{
		recoveryNetwork: &recoveryNetwork{guard: true},
		endpoints:       []net.Addr{&net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 443}},
	}
	dialed := false
	err := run(ctx, testIdentity, Config{ServerURL: "https://never-resolve.invalid", Token: "token", Network: network}, func(event Event) {
		if event.State == StateConnected {
			cancel()
		}
	}, func(_ context.Context, config tunnel.Config) (*clientConnection, error) {
		dialed = true
		if network.prepared != 1 || !network.guard || config.DialAddress != "192.0.2.1:443" || config.URL != "https://never-resolve.invalid" {
			t.Error("journal endpoint not prepared and pinned with original TLS authority")
		}
		return &clientConnection{
			packetConnection: &testConnection{closed: make(chan struct{})}, lease: tunnel.Lease{MTU: 1280},
		}, nil
	}, func(string, int) (device.PacketDevice, error) {
		return &testDevice{readStarted: make(chan struct{})}, nil
	})
	if !errors.Is(err, context.Canceled) || !dialed || lookups.Load() != 0 || network.guard || network.down != 1 {
		t.Fatalf("error=%v dialed=%t lookups=%d network=%+v", err, dialed, lookups.Load(), network)
	}
}

func TestCrashRecoveryPortMismatchRetainsProtection(t *testing.T) {
	lookups := denyPhysicalDNS(t)
	network := &journalRecoveryNetwork{
		recoveryNetwork: &recoveryNetwork{guard: true},
		endpoints:       []net.Addr{&net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 8443}},
	}
	err := run(context.Background(), testIdentity, Config{ServerURL: "https://never-resolve.invalid", Token: "token", Network: network}, nil,
		func(context.Context, tunnel.Config) (*clientConnection, error) {
			t.Fatal("dialed gateway without a matching cached endpoint")
			return nil, nil
		}, func(string, int) (device.PacketDevice, error) {
			t.Fatal("opened device without connection")
			return nil, nil
		})
	if err == nil || !network.guard || network.down != 0 || lookups.Load() != 0 {
		t.Fatalf("error=%v lookups=%d network=%+v", err, lookups.Load(), network)
	}
}

func TestDNSOnlyReconfigurationPreservesDeviceIdentity(t *testing.T) {
	for _, changedDNS := range []bool{false, true} {
		t.Run(map[bool]string{false: "unchanged lease", true: "changed DNS"}[changedDNS], func(t *testing.T) {
			testReconnectionPreservesDeviceIdentity(t, changedDNS)
		})
	}
}

func testReconnectionPreservesDeviceIdentity(t *testing.T, changedDNS bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tunDevice := &testDevice{readStarted: make(chan struct{})}
	network := &recoveryNetwork{}
	first := &testConnection{closed: make(chan struct{})}
	first.receive = func() ([]byte, error) {
		<-tunDevice.readStarted
		return nil, io.EOF
	}
	second := &testConnection{closed: make(chan struct{})}
	oldLease := tunnel.Lease{Address: netip.MustParsePrefix("10.0.0.2/32"), DNS: netip.MustParseAddr("10.0.0.1"), MTU: 1280}
	newLease := oldLease
	if changedDNS {
		newLease.DNS = netip.MustParseAddr("10.0.0.53")
	}
	network.reconfigure = func(lease tunnel.Lease) error {
		if tunDevice.closed.Load() || lease != newLease {
			t.Error("DNS reconfiguration changed adapter identity or retained old DNS")
		}
		return nil
	}
	attempts, opens, connected := 0, 0, 0
	err := run(ctx, testIdentity, Config{ServerURL: "https://192.0.2.1", Token: "token", Network: network, Reconnect: true}, func(event Event) {
		if event.State == StateConnected {
			connected++
			if connected == 2 {
				cancel()
			}
		}
	}, func(context.Context, tunnel.Config) (*clientConnection, error) {
		attempts++
		packets, lease := first, oldLease
		if attempts == 2 {
			packets, lease = second, newLease
		}
		return &clientConnection{packetConnection: packets, lease: lease}, nil
	}, func(string, int) (device.PacketDevice, error) {
		opens++
		return tunDevice, nil
	})
	if !errors.Is(err, context.Canceled) || opens != 1 || network.reconfigured != 1 || !tunDevice.closed.Load() || !tunDevice.readExited.Load() {
		t.Fatalf("error=%v opens=%d network=%+v", err, opens, network)
	}
}

func TestAutomaticNetworkRejectsUnsupportedEndpointsBeforeBootstrap(t *testing.T) {
	lookups := denyPhysicalDNS(t)
	for _, origin := range []string{
		"https://[fe80::1%25eth0]", "https://[fe80::1]", "https://[::1]",
		"https://127.0.0.1", "https://0.0.0.0", "https://[ff02::1]",
	} {
		t.Run(origin, func(t *testing.T) {
			network := &recoveryNetwork{}
			err := run(context.Background(), testIdentity, Config{ServerURL: origin, Token: "token", Network: network}, nil,
				func(context.Context, tunnel.Config) (*clientConnection, error) {
					t.Fatal("dialed unsupported automatic-network endpoint")
					return nil, nil
				}, func(string, int) (device.PacketDevice, error) {
					t.Fatal("opened device for unsupported endpoint")
					return nil, nil
				})
			if err == nil || network.prepared != 0 || network.guard || lookups.Load() != 0 {
				t.Fatalf("error=%v DNS lookups=%d network=%+v", err, lookups.Load(), network)
			}
		})
	}
}
