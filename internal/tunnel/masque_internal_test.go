package tunnel

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

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
	setMasqueHeaders(request, Config{ClientID: "laptop", Token: "secret"})
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
