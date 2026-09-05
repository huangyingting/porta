package clientapp

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/huangyingting/porta/internal/device"
	"github.com/huangyingting/porta/internal/tunnel"
	"github.com/quic-go/quic-go"
	"golang.org/x/net/http2"
)

func TestTransportClosureClassification(t *testing.T) {
	for _, test := range []struct {
		name  string
		err   error
		retry bool
	}{
		{"application shutdown", &quic.ApplicationError{ErrorCode: 0, Remote: true}, true},
		{"HTTP3 shutdown", &quic.ApplicationError{ErrorCode: 0x100, Remote: true}, true},
		{"HTTP3 cancellation", &quic.ApplicationError{ErrorCode: 0x10c, Remote: true}, true},
		{"stream shutdown", &quic.StreamError{ErrorCode: 0, Remote: true}, true},
		{"stream HTTP3 shutdown", &quic.StreamError{ErrorCode: 0x100, Remote: true}, true},
		{"stream cancellation", &quic.StreamError{ErrorCode: 0x10c, Remote: true}, true},
		{"transport shutdown", &quic.TransportError{ErrorCode: 0, Remote: true}, true},
		{"idle timeout", &quic.IdleTimeoutError{}, true},
		{"wrapped shutdown", fmt.Errorf("remote closed: %w", &quic.ApplicationError{ErrorCode: 0}), true},
		{"application protocol failure", &quic.ApplicationError{ErrorCode: 0x101, Remote: true}, false},
		{"stream protocol failure", &quic.StreamError{ErrorCode: 0x10e, Remote: true}, false},
		{"transport protocol failure", &quic.TransportError{ErrorCode: 0xa, Remote: true}, false},
		{"TLS failure", &quic.TransportError{ErrorCode: 0x128, Remote: true}, false},
		{"permanent stage", tunnel.PermanentError{Err: &quic.ApplicationError{ErrorCode: 0}}, false},
		{"permanent pointer stage", &tunnel.PermanentError{Err: &quic.StreamError{ErrorCode: 0x10c}}, false},
		{"joined certificate failure", errors.Join(&quic.ApplicationError{ErrorCode: 0}, x509.UnknownAuthorityError{}), false},
		{"joined application protocol failure", errors.Join(&quic.ApplicationError{ErrorCode: 0}, &quic.ApplicationError{ErrorCode: 0x101}), false},
		{"joined stream protocol failure", errors.Join(&quic.StreamError{ErrorCode: 0x10c}, &quic.StreamError{ErrorCode: 0x10e}), false},
		{"HTTP2 graceful shutdown", http2.GoAwayError{ErrCode: http2.ErrCodeNo}, true},
		{"HTTP2 canceled stream", http2.StreamError{Code: http2.ErrCodeCancel}, true},
		{"HTTP2 refused stream", &http2.StreamError{Code: http2.ErrCodeRefusedStream}, true},
		{"HTTP2 protocol failure", http2.GoAwayError{ErrCode: http2.ErrCodeProtocol}, false},
		{"HTTP2 stream protocol failure", http2.StreamError{Code: http2.ErrCodeProtocol}, false},
		{"HTTP2 stream certificate cause", http2.StreamError{Code: http2.ErrCodeCancel, Cause: x509.UnknownAuthorityError{}}, false},
		{"joined HTTP2 protocol failure", errors.Join(http2.GoAwayError{ErrCode: http2.ErrCodeNo}, http2.GoAwayError{ErrCode: http2.ErrCodeProtocol}), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := tunnel.IsRetryable(test.err); got != test.retry {
				t.Errorf("IsRetryable(%v) = %t, want %t", test.err, got, test.retry)
			}
			if tunnel.IsTransportUnavailable(test.err) {
				t.Error("unclassified connection closure permits downgrade")
			}
			if got := tunnel.IsTransportUnavailable(tunnel.TransportUnavailableError{Err: test.err}); got != test.retry {
				t.Errorf("classified transport-unavailable = %t, want %t", got, test.retry)
			}
		})
	}
}

func TestEstablishedTransportNormalClosuresReconnect(t *testing.T) {
	for _, test := range []struct {
		name      string
		err       error
		transport tunnel.Transport
	}{
		{"application shutdown", &quic.ApplicationError{ErrorCode: 0, Remote: true}, tunnel.TransportHTTP3},
		{"HTTP3 shutdown", &quic.ApplicationError{ErrorCode: 0x100, Remote: true}, tunnel.TransportHTTP3},
		{"application cancellation", &quic.ApplicationError{ErrorCode: 0x10c, Remote: true}, tunnel.TransportHTTP3},
		{"stream cancellation", &quic.StreamError{ErrorCode: 0x10c, Remote: true}, tunnel.TransportHTTP3},
		{"transport shutdown", &quic.TransportError{ErrorCode: 0, Remote: true}, tunnel.TransportHTTP3},
		{"idle timeout", &quic.IdleTimeoutError{}, tunnel.TransportHTTP3},
		{"HTTP2 graceful shutdown", http2.GoAwayError{ErrCode: http2.ErrCodeNo}, tunnel.TransportHTTP2},
		{"HTTP2 canceled stream", http2.StreamError{Code: http2.ErrCodeCancel}, tunnel.TransportHTTP2},
		{"HTTP2 refused stream", http2.StreamError{Code: http2.ErrCodeRefusedStream}, tunnel.TransportHTTP2},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			tunDevice := &testDevice{readStarted: make(chan struct{})}
			first := &testConnection{closed: make(chan struct{})}
			first.receive = func() ([]byte, error) {
				<-tunDevice.readStarted
				return nil, test.err
			}
			second := &testConnection{closed: make(chan struct{})}
			attempts, connected := 0, 0
			err := run(ctx, Config{
				ServerURL: "https://gateway.invalid", Token: "token", Transport: test.transport, Reconnect: true,
			}, func(event Event) {
				if event.State == StateConnected {
					connected++
					if connected == 2 {
						cancel()
					}
				}
			}, func(_ context.Context, config tunnel.Config) (*clientConnection, error) {
				attempts++
				if config.Transport != test.transport {
					t.Fatal("established shutdown downgraded explicit transport")
				}
				connection := first
				if attempts == 2 {
					connection = second
				}
				return &clientConnection{packetConnection: connection, lease: tunnel.Lease{MTU: 1280}}, nil
			}, func(string, int) (device.PacketDevice, error) { return tunDevice, nil })
			if !errors.Is(err, context.Canceled) || attempts != 2 || connected != 2 || !tunDevice.closed.Load() || !tunDevice.readExited.Load() {
				t.Fatalf("error=%v attempts=%d connected=%d closed=%t readerExited=%t", err, attempts, connected, tunDevice.closed.Load(), tunDevice.readExited.Load())
			}
		})
	}
}

func TestEstablishedTransportProtocolFailuresStop(t *testing.T) {
	for _, failure := range []error{
		&quic.ApplicationError{ErrorCode: 0x101, Remote: true},
		&quic.StreamError{ErrorCode: 0x10e, Remote: true},
		&quic.TransportError{ErrorCode: 0x128, Remote: true},
		http2.StreamError{Code: http2.ErrCodeProtocol},
		http2.GoAwayError{ErrCode: http2.ErrCodeProtocol},
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		tunDevice := &testDevice{readStarted: make(chan struct{})}
		connection := &testConnection{closed: make(chan struct{})}
		connection.receive = func() ([]byte, error) {
			<-tunDevice.readStarted
			return nil, failure
		}
		reconnecting := false
		err := runTestClient(ctx, Config{Reconnect: true}, func(event Event) {
			if event.State == StateReconnecting {
				reconnecting = true
			}
		}, connection, tunDevice)
		cancel()
		if !errors.Is(err, failure) || reconnecting || !tunDevice.closed.Load() || !tunDevice.readExited.Load() {
			t.Fatalf("error=%v reconnecting=%t closed=%t readerExited=%t", err, reconnecting, tunDevice.closed.Load(), tunDevice.readExited.Load())
		}
	}

}

func TestGatewayResponseRetryClassification(t *testing.T) {
	for _, status := range []int{408, 425, 429, 500, 502, 503, 504} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			response := &tunnel.GatewayResponseError{StatusCode: status, Status: http.StatusText(status)}
			for _, err := range []error{response, tunnel.TransportUnavailableError{Err: response}} {
				if !tunnel.IsRetryable(err) || tunnel.IsTransportUnavailable(err) {
					t.Fatalf("temporary response must retry without downgrade: %v", err)
				}
			}
			if tunnel.IsRetryable(tunnel.PermanentError{Err: response}) {
				t.Fatal("permanent stage classification lost")
			}
		})
	}
	for _, status := range []int{404, 405, 421, 426, 501, 505} {
		response := &tunnel.GatewayResponseError{StatusCode: status, Status: http.StatusText(status)}
		if tunnel.IsRetryable(response) || tunnel.IsTransportUnavailable(response) {
			t.Fatalf("response %d retried without explicit unavailable classification", status)
		}
		unavailable := tunnel.TransportUnavailableError{Err: response}
		if !tunnel.IsRetryable(unavailable) || !tunnel.IsTransportUnavailable(unavailable) {
			t.Fatalf("explicit transport capability failure %d did not permit fallback", status)
		}
	}
	for _, response := range []*tunnel.GatewayResponseError{
		{StatusCode: 301}, {StatusCode: 400}, {StatusCode: 401}, {StatusCode: 403},
		{StatusCode: 407}, {StatusCode: 409}, {StatusCode: 410}, {StatusCode: 422}, {StatusCode: 507},
		{StatusCode: 426, ServerMinVersion: "2", ServerMaxVersion: "3"},
	} {
		for _, err := range []error{response, tunnel.TransportUnavailableError{Err: response}, errors.Join(context.DeadlineExceeded, response)} {
			if tunnel.IsRetryable(err) || tunnel.IsTransportUnavailable(err) {
				t.Fatalf("permanent gateway response %d retried or downgraded: %v", response.StatusCode, err)
			}
		}
	}
}

func TestStartupGatewaySlownessAndLeaseWaitRetryWithoutDowngrade(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
	}{
		{"temporary gateway response", &tunnel.GatewayResponseError{StatusCode: http.StatusServiceUnavailable}},
		{"authenticated lease timeout", fmt.Errorf("wait for ADDRESS_ASSIGN: %w", context.DeadlineExceeded)},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			attempts := 0
			err := run(ctx, Config{ServerURL: "https://gateway.invalid", Token: "token", Reconnect: true}, func(event Event) {
				if event.State == StateConnected {
					cancel()
				}
			}, func(_ context.Context, config tunnel.Config) (*clientConnection, error) {
				attempts++
				if config.Transport != tunnel.TransportHTTP3 {
					t.Fatal("temporary authenticated failure downgraded transport")
				}
				if attempts == 1 {
					return nil, test.err
				}
				return &clientConnection{
					packetConnection: &testConnection{closed: make(chan struct{})}, lease: tunnel.Lease{MTU: 1280},
				}, nil
			}, func(string, int) (device.PacketDevice, error) {
				return &testDevice{readStarted: make(chan struct{})}, nil
			})
			if !errors.Is(err, context.Canceled) || attempts != 2 {
				t.Fatalf("error=%v attempts=%d", err, attempts)
			}
		})
	}
}
