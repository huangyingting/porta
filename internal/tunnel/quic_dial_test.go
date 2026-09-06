package tunnel

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"testing"
	"testing/synctest"
	"time"

	"github.com/quic-go/quic-go"
)

func TestQUICResolutionInterleavesAddressFamilies(t *testing.T) {
	got, err := resolveQUICAddressesWithLookup(context.Background(), "gateway.test:443",
		func(context.Context, string, string) ([]netip.Addr, error) {
			return []netip.Addr{
				netip.MustParseAddr("2001:db8::1"),
				netip.MustParseAddr("2001:db8::2"),
				netip.MustParseAddr("192.0.2.1"),
				netip.MustParseAddr("192.0.2.2"),
			}, nil
		})
	want := []string{"[2001:db8::1]:443", "192.0.2.1:443", "[2001:db8::2]:443", "192.0.2.2:443"}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("resolved order = %v, %v; want %v", got, err, want)
	}
}

func TestQUICDialAcceleratesImmediateFailure(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		start := time.Now()
		var attempts []string
		_, err := dialQUICAddressesWithDial(context.Background(), []string{"first", "second"},
			func(_ context.Context, address string) (*quic.Conn, error) {
				attempts = append(attempts, address)
				return nil, net.ErrClosed
			}, 250*time.Millisecond)
		if !errors.Is(err, net.ErrClosed) || !reflect.DeepEqual(attempts, []string{"first", "second"}) {
			t.Fatalf("attempts = %v, error = %v", attempts, err)
		}
		if elapsed := time.Since(start); elapsed != 0 {
			t.Fatalf("immediate failure delayed alternate by %v", elapsed)
		}
		t.Logf("alternate start after immediate failure: %v", time.Since(start))
	})
}

func TestQUICDialStaggersPendingAddresses(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		start := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		starts := make(chan time.Duration, 3)
		_, err := dialQUICAddressesWithDial(ctx, []string{"first", "second", "third"},
			func(ctx context.Context, _ string) (*quic.Conn, error) {
				starts <- time.Since(start)
				<-ctx.Done()
				return nil, ctx.Err()
			}, 250*time.Millisecond)
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal(err)
		}
		for _, want := range []time.Duration{0, 250 * time.Millisecond, 500 * time.Millisecond} {
			select {
			case got := <-starts:
				if got != want {
					t.Fatalf("attempt started at %v, want %v", got, want)
				}
			default:
				t.Fatalf("missing attempt at %v", want)
			}
		}
	})
}

func TestQUICDialPreservesPermanentFailureBeforeDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		start := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		failure := &tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}}
		_, err := dialQUICAddressesWithDial(ctx, []string{"bad-certificate", "unreachable"},
			func(ctx context.Context, address string) (*quic.Conn, error) {
				if address == "bad-certificate" {
					return nil, failure
				}
				<-ctx.Done()
				return nil, ctx.Err()
			}, 250*time.Millisecond)
		if !errors.Is(err, failure) || !isPermanent(err) || IsRetryable(preSessionFailure(err)) {
			t.Fatalf("certificate failure became retryable transport failure: %v", err)
		}
		if elapsed := time.Since(start); elapsed != 0 {
			t.Fatalf("permanent failure waited for unreachable alternate: %v", elapsed)
		}
		t.Logf("permanent failure returned after %v", time.Since(start))
	})
}

func TestQUICDialCancellationStopsPendingAttempts(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		started := make(chan struct{})
		stopped := make(chan struct{})
		var attempts int
		done := make(chan error, 1)
		go func() {
			_, err := dialQUICAddressesWithDial(ctx, []string{"first", "second", "third"},
				func(ctx context.Context, address string) (*quic.Conn, error) {
					attempts++
					if address != "first" {
						t.Errorf("canceled race started %q", address)
					}
					close(started)
					<-ctx.Done()
					close(stopped)
					return nil, ctx.Err()
				}, 250*time.Millisecond)
			done <- err
		}()
		<-started
		cancel()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled race = %v", err)
		}
		<-stopped
		synctest.Wait()
		if attempts != 1 {
			t.Fatalf("attempts after cancellation = %d, want 1", attempts)
		}
	})
}

func TestQUICDialWinnerSurvivesAttemptCancellation(t *testing.T) {
	listener, tlsConfig := newQUICDialTestListener(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	dialCtx, stopDial := context.WithCancel(ctx)
	connection, err := dialQUICAddresses(dialCtx, []string{listener.Addr().String(), listener.Addr().String()}, tlsConfig, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.CloseWithError(0, "")
	stopDial()
	peer, err := listener.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer peer.CloseWithError(0, "")
	assertQUICDialRoundTrip(t, ctx, connection, peer)
}

func TestQUICDialCleansUpLateSuccess(t *testing.T) {
	for _, outcome := range []string{"winner", "canceled", "permanent"} {
		t.Run(outcome, func(t *testing.T) {
			listener, tlsConfig := newQUICDialTestListener(t)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			var connections, peers [2]*quic.Conn
			for index := range connections {
				connection, err := quic.DialAddr(ctx, listener.Addr().String(), tlsConfig, nil)
				if err != nil {
					t.Fatal(err)
				}
				defer connection.CloseWithError(0, "")
				peer, err := listener.Accept(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer peer.CloseWithError(0, "")
				connections[index], peers[index] = connection, peer
			}
			dialCtx, stopDial := context.WithCancel(ctx)
			defer stopDial()
			release := [2]chan struct{}{make(chan struct{}), make(chan struct{})}
			started := make(chan struct{}, 2)
			done := make(chan error, 1)
			failure := &tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}}
			go func() {
				_, err := dialQUICAddressesWithDial(dialCtx, []string{"first", "second"},
					func(_ context.Context, address string) (*quic.Conn, error) {
						index := 0
						if address == "second" {
							index = 1
						}
						started <- struct{}{}
						<-release[index]
						if index == 0 && outcome == "permanent" {
							return nil, failure
						}
						return connections[index], nil
					}, 0)
				done <- err
			}()
			<-started
			<-started
			if outcome == "canceled" {
				stopDial()
			} else {
				close(release[0])
			}
			err := <-done
			if outcome == "canceled" {
				close(release[0])
				if !errors.Is(err, context.Canceled) {
					t.Errorf("cancellation error = %v", err)
				}
			} else if outcome == "permanent" {
				if !errors.Is(err, failure) {
					t.Errorf("permanent error = %v", err)
				}
			} else if err != nil {
				t.Errorf("winner error = %v", err)
			}
			close(release[1])
			select {
			case <-connections[1].Context().Done():
			case <-ctx.Done():
				t.Fatal("late successful connection was not closed")
			}
			if outcome == "winner" {
				assertQUICDialRoundTrip(t, ctx, connections[0], peers[0])
			} else if outcome == "canceled" {
				select {
				case <-connections[0].Context().Done():
				case <-ctx.Done():
					t.Fatal("canceled race retained its first connection")
				}
			}
		})
	}
}

func TestQUICDialRejectsRealCertificateFailure(t *testing.T) {
	listener, tlsConfig := newQUICDialTestListener(t)
	tlsConfig.InsecureSkipVerify = false
	blackhole, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer blackhole.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err = dialQUICAddresses(ctx, []string{listener.Addr().String(), blackhole.LocalAddr().String()}, tlsConfig, nil)
	if !isPermanent(err) || IsTransportUnavailable(preSessionFailure(err)) {
		t.Fatalf("untrusted certificate was masked by unreachable alternate: %v", err)
	}
}

func newQUICDialTestListener(t *testing.T) (*quic.Listener, *tls.Config) {
	t.Helper()
	certServer := httptest.NewTLSServer(nil)
	serverTLS := certServer.TLS.Clone()
	certServer.Close()
	serverTLS.NextProtos = []string{"quic-dial-test"}
	listener, err := quic.ListenAddr("127.0.0.1:0", serverTLS, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	return listener, &tls.Config{NextProtos: serverTLS.NextProtos, InsecureSkipVerify: true}
}

func assertQUICDialRoundTrip(t *testing.T, ctx context.Context, connection, peer *quic.Conn) {
	t.Helper()
	stream, err := connection.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_ = stream.SetDeadline(time.Now().Add(time.Second))
	if _, err := stream.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	received, err := peer.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_ = received.SetDeadline(time.Now().Add(time.Second))
	body, err := io.ReadAll(received)
	if err != nil || string(body) != "request" {
		t.Fatalf("winning connection request = %q, %v", body, err)
	}
	if _, err := received.Write([]byte("response")); err != nil {
		t.Fatal(err)
	}
	if err := received.Close(); err != nil {
		t.Fatal(err)
	}
	body, err = io.ReadAll(stream)
	if err != nil || string(body) != "response" {
		t.Fatalf("winning connection response = %q, %v", body, err)
	}
}
