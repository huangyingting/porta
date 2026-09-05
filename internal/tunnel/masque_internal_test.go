package tunnel

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/huangyingting/porta/internal/deviceauth"

	"github.com/huangyingting/porta/internal/masque"
	"github.com/huangyingting/porta/internal/protocol"
	"github.com/quic-go/quic-go/http3"
)

func TestMasqueDeliveryBackpressuresInsteadOfDisconnecting(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client := &masqueClient{
		ctx:     ctx,
		packets: make(chan []byte, 1),
		errors:  make(chan error, 1),
	}
	client.deliver([]byte{1})

	delivered := make(chan struct{})
	go func() {
		client.deliver([]byte{2})
		close(delivered)
	}()

	select {
	case <-delivered:
		t.Fatal("delivery did not apply backpressure when the queue was full")
	case err := <-client.errors:
		t.Fatalf("full receive queue reported a fatal error: %v", err)
	case <-time.After(20 * time.Millisecond):
	}

	<-client.packets
	select {
	case <-delivered:
	case <-time.After(time.Second):
		t.Fatal("delivery did not resume after receive capacity became available")
	}
}

func TestMasqueProtocolHeaders(t *testing.T) {
	request, err := http.NewRequest(http.MethodConnect, "https://vpn.example.com/", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := setMasqueHeaders(request, Config{
		Token: "secret",
		DeviceProof: func(string, string) (deviceauth.Proof, error) {
			return deviceauth.Proof{DeviceID: "d-AAAAAAAAAAAAAAAAAAAAAA"}, nil
		},
	}); err != nil {
		t.Fatal(err)
	}
	if got := request.Header.Get(protocol.HeaderVersion); got != protocol.Version {
		t.Fatalf("protocol version = %q, want %q", got, protocol.Version)
	}
}

func TestValidateMasqueResponseProtocolVersion(t *testing.T) {
	response := &http.Response{
		StatusCode: http.StatusUpgradeRequired,
		Status:     "426 Upgrade Required",
		Header: http.Header{
			protocol.HeaderMinVersion: {protocol.MinVersion},
			protocol.HeaderMaxVersion: {protocol.MaxVersion},
		},
		Body: io.NopCloser(strings.NewReader("")),
	}

	err := validateMasqueResponse(response)
	want := "gateway requires Porta protocol " + protocol.Version + "; client uses " + protocol.Version
	if err == nil || err.Error() != want {
		t.Fatalf("upgrade error = %v", err)
	}

	response = &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Header: http.Header{
			http3.CapsuleProtocolHeader: {"?1"},
			protocol.HeaderVersion:      {protocol.Version},
		},
		Body: io.NopCloser(strings.NewReader("")),
	}
	if err := validateMasqueResponse(response); err != nil {
		t.Fatalf("current protocol response rejected: %v", err)
	}

	response.Header.Del(protocol.HeaderVersion)
	if err := validateMasqueResponse(response); err == nil {
		t.Fatal("response without a protocol version was accepted")
	}
}

func TestInvalidLeaseIsPermanent(t *testing.T) {
	for _, value := range []string{"0.0.0.0/32", "127.0.0.1/32", "224.0.0.1/32", "10.66.0.0/24", "2001:db8::1/128"} {
		t.Run(value, func(t *testing.T) {
			payload, err := masque.EncodeAddressAssign([]masque.Address{{RequestID: masqueRequestID, Prefix: netip.MustParsePrefix(value)}})
			if err != nil {
				t.Fatal(err)
			}
			var stream bytes.Buffer
			if err := masque.NewEncoder(&stream).Write(masque.CapsuleAddressAssign, payload); err != nil {
				t.Fatal(err)
			}
			client := &masqueClient{
				ctx: context.Background(), decoder: masque.NewDecoder(&stream),
				errors: make(chan error, 1), leaseReady: make(chan netip.Prefix, 1),
			}
			client.readCapsules()
			select {
			case err := <-client.errors:
				if IsRetryable(err) || IsTransportUnavailable(err) || !isPermanent(err) {
					t.Fatalf("invalid lease not classified permanently: %v", err)
				}
			default:
				t.Fatal("invalid lease was silently ignored")
			}
		})
	}
}

func TestInvalidLeaseHeadersArePermanent(t *testing.T) {
	for _, test := range []struct{ header, value string }{
		{"X-Porta-MTU", "invalid"}, {"X-Porta-MTU", "575"}, {"X-Porta-MTU", "9001"},
		{"X-Porta-DNS", "not-an-address"}, {"X-Porta-DNS", "0.0.0.0"}, {"X-Porta-DNS", "ff02::1"},
		{"X-Porta-DNS", "127.0.0.53"}, {"X-Porta-DNS", "169.254.1.1"},
	} {
		response := &http.Response{StatusCode: http.StatusOK, Header: make(http.Header)}
		response.Header.Set(http3.CapsuleProtocolHeader, "?1")
		response.Header.Set(protocol.HeaderVersion, protocol.Version)
		response.Header.Set(test.header, test.value)
		if err := validateMasqueResponse(response); err == nil || !isPermanent(err) {
			t.Fatalf("%s=%s did not produce permanent rejection: %v", test.header, test.value, err)
		}
	}
}

func BenchmarkMasqueDelivery(b *testing.B) {
	client := &masqueClient{
		ctx:     context.Background(),
		packets: make(chan []byte, 1),
	}
	packet := make([]byte, 1100)
	b.SetBytes(int64(len(packet)))
	b.ReportAllocs()
	for b.Loop() {
		client.deliver(packet)
		<-client.packets
	}
}

func TestMasqueEndpointDefaultsAndValidatesPort(t *testing.T) {
	for _, test := range []struct{ origin, host string }{
		{"https://vpn.example.com", "vpn.example.com:443"},
		{"https://vpn.example.com:8443/", "vpn.example.com:8443"},
		{"https://[2001:db8::1]", "[2001:db8::1]:443"},
	} {
		t.Run(test.origin, func(t *testing.T) {
			endpoint, err := masqueEndpoint(test.origin)
			if err != nil || endpoint.Host != test.host {
				t.Fatalf("endpoint = %v, %v; want host %s", endpoint, err, test.host)
			}
		})
	}
	for _, origin := range []string{"https://:443", "https://vpn.example.com:0", "https://vpn.example.com:65536"} {
		if _, err := masqueEndpoint(origin); err == nil {
			t.Fatalf("invalid origin %s accepted", origin)
		}
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type closeTrackingBody struct {
	io.Reader
	closed chan struct{}
	once   sync.Once
}

func (b *closeTrackingBody) Close() error {
	b.once.Do(func() { close(b.closed) })
	return nil
}

func TestTimedRoundTripClosesLateResponse(t *testing.T) {
	body := &closeTrackingBody{Reader: strings.NewReader("late"), closed: make(chan struct{})}
	release := make(chan struct{})
	request, err := http.NewRequest(http.MethodConnect, "https://vpn.example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	transport := roundTripperFunc(func(*http.Request) (*http.Response, error) {
		<-release
		return &http.Response{Body: body}, nil
	})
	_, err = timedRoundTrip(context.Background(), transport, request, time.Millisecond)
	close(release)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timeout = %v", err)
	}
	select {
	case <-body.closed:
	case <-time.After(time.Second):
		t.Fatal("late response body leaked after timeout")
	}
}

func TestTimedRoundTripKeepsSuccessfulStreamAlive(t *testing.T) {
	var requestCtx context.Context
	transport := roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		requestCtx = r.Context()
		return &http.Response{Body: io.NopCloser(strings.NewReader("packet"))}, nil
	})
	request, _ := http.NewRequest(http.MethodConnect, "https://vpn.example.com", nil)
	response, err := timedRoundTrip(context.Background(), transport, request, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if requestCtx.Err() != nil {
		t.Fatal("successful stream canceled before use")
	}
	if err := response.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(requestCtx.Err(), context.Canceled) {
		t.Fatal("closing response did not release its context")
	}
}

func TestMasqueDeliveryTransfersOwnedPacket(t *testing.T) {
	client := &masqueClient{ctx: context.Background(), packets: make(chan []byte, 2)}
	first := []byte{1, 2, 3}
	second := []byte{4, 5, 6}
	client.deliver(first)
	client.deliver(second)
	if received := <-client.packets; &received[0] != &first[0] {
		t.Fatal("delivery copied an already-owned packet")
	}
	if received := <-client.packets; &received[0] != &second[0] {
		t.Fatal("delivery did not preserve independent packet storage")
	}
}

func TestTimedRoundTripClosesErrorResponse(t *testing.T) {
	body := &closeTrackingBody{Reader: strings.NewReader("failed"), closed: make(chan struct{})}
	failure := errors.New("failed CONNECT")
	var requestCtx context.Context
	transport := roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		requestCtx = r.Context()
		return &http.Response{Body: body}, failure
	})
	request, _ := http.NewRequest(http.MethodConnect, "https://vpn.example.com", nil)
	if _, err := timedRoundTrip(context.Background(), transport, request, time.Second); !errors.Is(err, failure) {
		t.Fatalf("error = %v, want %v", err, failure)
	}
	select {
	case <-body.closed:
	default:
		t.Fatal("response accompanying a transport error was not closed")
	}
	if requestCtx.Err() == nil {
		t.Fatal("failed request context was not canceled")
	}
}
