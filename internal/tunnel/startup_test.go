package tunnel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"testing"
	"time"

	"github.com/huangyingting/porta/internal/masque"
)

func TestStartupTimeoutInterruptsControlWrite(t *testing.T) {
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	finished := make(chan error, 1)
	go func() {
		_, err := establishWithTimeout(context.Background(), 20*time.Millisecond, func(ctx context.Context) (*Conn, error) {
			stop := context.AfterFunc(ctx, func() { _ = writer.CloseWithError(ctx.Err()) })
			defer stop()
			return nil, masque.NewEncoder(writer).Write(masque.CapsuleAddressRequest, []byte{1})
		})
		finished <- err
	}()
	select {
	case err := <-finished:
		if !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			t.Fatalf("startup error = %v, want deadline exceeded", err)
		}
	case <-time.After(time.Second):
		t.Fatal("control write outlived startup timeout")
	}
}

func TestStartupTimeoutDoesNotExpireEstablishedTunnel(t *testing.T) {
	var sessionCtx context.Context
	connection, err := establishWithTimeout(context.Background(), 20*time.Millisecond, func(ctx context.Context) (*Conn, error) {
		sessionCtx = ctx
		return &Conn{closePacket: func() error { return nil }}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	select {
	case <-sessionCtx.Done():
		t.Fatal("established tunnel retained the startup deadline")
	case <-time.After(50 * time.Millisecond):
	}
	_ = connection.Close()
	if !errors.Is(sessionCtx.Err(), context.Canceled) {
		t.Fatal("closing tunnel did not release its lifetime context")
	}
}

func TestStartupPreservesFailureAndCancelsLifetime(t *testing.T) {
	failure := &GatewayResponseError{StatusCode: 401, Status: "401 Unauthorized"}
	var sessionCtx context.Context
	_, err := establishWithTimeout(context.Background(), time.Second, func(ctx context.Context) (*Conn, error) {
		sessionCtx = ctx
		return nil, failure
	})
	if err != failure || sessionCtx.Err() == nil {
		t.Fatalf("failure = %v, lifetime error = %v", err, sessionCtx.Err())
	}
}

func TestQUICResolutionRespectsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := resolveQUICAddresses(ctx, "vpn.example.com:443"); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled resolution = %v", err)
	}
	for _, address := range []string{"127.0.0.1:443", "[::1]:8443", "[fe80::1%lo]:443"} {
		resolved, err := resolveQUICAddresses(context.Background(), address)
		if err != nil || len(resolved) != 1 || resolved[0] != address {
			t.Fatalf("numeric resolution = %v, %v; want %s", resolved, err, address)
		}
	}
	resolved, err := resolveQUICAddressesWithLookup(
		context.Background(),
		"vpn.example.com:443",
		func(context.Context, string, string) ([]netip.Addr, error) {
			return []netip.Addr{
				netip.MustParseAddr("2001:db8::1"),
				netip.MustParseAddr("192.0.2.10"),
			}, nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"[2001:db8::1]:443", "192.0.2.10:443"}
	if len(resolved) != len(want) || resolved[0] != want[0] || resolved[1] != want[1] {
		t.Fatalf("resolved addresses = %v, want %v", resolved, want)
	}
}

func TestStartupDeadlinePreservesRecoveryCategory(t *testing.T) {
	for _, stage := range []string{"transport", "lease", "permanent"} {
		t.Run(stage, func(t *testing.T) {
			_, err := establishWithTimeout(context.Background(), 10*time.Millisecond, func(ctx context.Context) (*Conn, error) {
				<-ctx.Done()
				switch stage {
				case "transport":
					return nil, TransportUnavailableError{Err: ctx.Err()}
				case "lease":
					return nil, fmt.Errorf("wait for ADDRESS_ASSIGN: %w", ctx.Err())
				default:
					return nil, PermanentError{Err: ctx.Err()}
				}
			})
			if !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
				t.Fatalf("deadline classification = %v", err)
			}
			if IsTransportUnavailable(err) != (stage == "transport") || IsRetryable(err) != (stage != "permanent") {
				t.Fatalf("wrong recovery category for %s: %v", stage, err)
			}
		})
	}
}
