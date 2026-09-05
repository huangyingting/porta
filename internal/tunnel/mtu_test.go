package tunnel

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/huangyingting/porta/internal/masque"
)

func mtuTestClient(t *testing.T, wire io.Reader, writer io.Writer) *masqueClient {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	header := make(http.Header)
	header.Set("X-Porta-MTU", "1280")
	header.Set(masque.MTUDiscoveryHeader, "000102030405060708090a0b0c0d0e0f")
	client := newMasqueClient(ctx, cancel, masque.NewEncoder(writer), masque.NewDecoder(wire), header)
	client.sendDatagram = func(data []byte) error {
		probe, err := masque.DecodeMTUProbe(data)
		if err != nil {
			return err
		}
		client.mtuDiscovery.echoes <- probe
		return nil
	}
	client.receiveDatagram = func(context.Context) ([]byte, error) { return nil, io.EOF }
	if err := client.configureMTU(header); err != nil {
		t.Fatal(err)
	}
	return client
}

func TestMTUOfferRequiresDatagramsAndValidCeiling(t *testing.T) {
	for _, test := range []struct {
		name, offer, mtu string
		datagrams        bool
	}{
		{"bad-token", "invalid", "1280", true},
		{"missing-ceiling", "000102030405060708090a0b0c0d0e0f", "", true},
		{"too-small", "000102030405060708090a0b0c0d0e0f", "1100", true},
		{"too-large", "000102030405060708090a0b0c0d0e0f", "10000", true},
		{"HTTP2", "000102030405060708090a0b0c0d0e0f", "1280", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			header := make(http.Header)
			header.Set("X-Porta-MTU", test.mtu)
			header.Set(masque.MTUDiscoveryHeader, test.offer)
			client := &masqueClient{}
			if test.datagrams {
				client.sendDatagram = func([]byte) error { return nil }
				client.receiveDatagram = func(context.Context) ([]byte, error) { return nil, io.EOF }
			}
			if err := client.configureMTU(header); !isPermanent(err) || IsTransportUnavailable(err) {
				t.Fatalf("invalid offer must fail without transport downgrade: %v", err)
			}
		})
	}
	client := &masqueClient{}
	if err := client.configureMTU(make(http.Header)); err != nil || client.mtuDiscovery != nil {
		t.Fatalf("absent offer changed fixed mode: %v", err)
	}
}

func TestMTURequiresMatchingReliableSelection(t *testing.T) {
	for _, selected := range []int{1280, 1100} {
		var wire bytes.Buffer
		client := mtuTestClient(t, bytes.NewReader(nil), &wire)
		client.mtuDiscovery.selected <- selected
		err := client.selectMTU(context.Background())
		if selected == 1280 {
			if err != nil || client.lease.MTU != selected {
				t.Fatalf("confirmed selection = %d, %v", client.lease.MTU, err)
			}
		} else if !isPermanent(err) || IsTransportUnavailable(err) {
			t.Fatalf("mismatched selection not rejected: %v", err)
		}
		capsule, err := masque.NewDecoder(&wire).Read()
		if err != nil || capsule.Type != masque.CapsuleMTUSelect {
			t.Fatalf("selection not sent on reliable control stream: %+v, %v", capsule, err)
		}
		mtu, err := masque.DecodeMTUSelection(capsule.Value, client.mtuDiscovery.token)
		if err != nil || mtu != 1280 {
			t.Fatalf("client requested unconfirmed MTU: %d, %v", mtu, err)
		}
	}
}

func TestMTUAgreementTimeoutDoesNotReturnPartiallyConfiguredLease(t *testing.T) {
	var wire bytes.Buffer
	client := mtuTestClient(t, bytes.NewReader(nil), &wire)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := client.selectMTU(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("missing reliable acknowledgement accepted: %v", err)
	}
}

func TestMTUProbesInCapsulesCannotConfirmDatagramDelivery(t *testing.T) {
	var wire bytes.Buffer
	client := mtuTestClient(t, &wire, io.Discard)
	data, err := masque.EncodeMTUProbe(masque.MTUProbe{Token: client.mtuDiscovery.token, Sequence: 1, Size: 1200})
	if err != nil {
		t.Fatal(err)
	}
	if err := masque.NewEncoder(&wire).Write(masque.CapsuleDatagram, data); err != nil {
		t.Fatal(err)
	}
	client.readCapsules()
	if len(client.mtuDiscovery.echoes) != 0 || len(client.packets) != 0 {
		t.Fatal("capsule fallback incorrectly proved datagram delivery")
	}
	if err := <-client.errors; !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
}

func TestMTUSelectedCapsuleValidatesToken(t *testing.T) {
	var wire bytes.Buffer
	client := mtuTestClient(t, &wire, io.Discard)
	token := client.mtuDiscovery.token
	token[0]++
	if err := masque.NewEncoder(&wire).Write(masque.CapsuleMTUSelected, masque.EncodeMTUSelection(token, 1200)); err != nil {
		t.Fatal(err)
	}
	client.readCapsules()
	if err := <-client.errors; !isPermanent(err) || IsTransportUnavailable(err) {
		t.Fatalf("unrelated selection accepted: %v", err)
	}
}
