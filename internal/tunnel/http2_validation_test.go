package tunnel

import (
	"io"
	"net/http"
	"net/netip"
	"strings"
	"testing"

	"github.com/huangyingting/porta/internal/protocol"
)

func TestHTTP2LeaseHeadersValidateAndPopulateLease(t *testing.T) {
	header := validHTTP2LeaseHeader()
	lease, err := leaseFromHTTP2Headers(header)
	if err != nil {
		t.Fatal(err)
	}
	if lease.Address != netip.MustParsePrefix("10.66.0.2/29") ||
		lease.Gateway != netip.MustParseAddr("10.66.0.1") ||
		lease.DNS != netip.MustParseAddr("1.1.1.1") ||
		lease.MTU != 1300 {
		t.Fatalf("unexpected HTTP/2 lease: %+v", lease)
	}

	for _, test := range []struct {
		name, header, value string
	}{
		{"address", "X-Porta-Address", "127.0.0.1/32"},
		{"prefix", "X-Porta-Address", "10.66.0.2/8"},
		{"gateway", "X-Porta-Gateway", "10.66.1.1"},
		{"dns", "X-Porta-DNS", "169.254.1.1"},
		{"mtu", "X-Porta-MTU", "575"},
	} {
		t.Run(test.name, func(t *testing.T) {
			invalid := header.Clone()
			invalid.Set(test.header, test.value)
			if _, err := leaseFromHTTP2Headers(invalid); err == nil || !isPermanent(err) {
				t.Fatalf("invalid lease header accepted: %v", err)
			}
		})
	}
}

func TestHTTP2ResponseRequiresFramingAndLaneIdentity(t *testing.T) {
	header := validHTTP2LeaseHeader()
	header.Set("Content-Type", protocol.ContentType)
	header.Set(protocol.HeaderVersion, protocol.Version)
	header.Set("X-Porta-Lane-Session", "session-12345678")
	header.Set("X-Porta-Lane", "2")
	header.Set("X-Porta-Lanes", "4")
	response := &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		ProtoMajor: 2,
		Header:     header,
		Body:       io.NopCloser(strings.NewReader("")),
	}
	if err := validateHTTP2TunnelResponse(response, "session-12345678", 2); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(http.Header){
		func(header http.Header) { header.Set("Content-Type", "application/octet-stream") },
		func(header http.Header) { header.Set(protocol.HeaderVersion, "99") },
		func(header http.Header) { header.Set("X-Porta-Lane", "3") },
		func(header http.Header) { header.Set("X-Porta-Lane-Session", "different-session") },
	} {
		invalid := *response
		invalid.Header = response.Header.Clone()
		mutate(invalid.Header)
		if err := validateHTTP2TunnelResponse(&invalid, "session-12345678", 2); err == nil || !isPermanent(err) {
			t.Fatalf("invalid lane response accepted: %v", err)
		}
	}
}

func validHTTP2LeaseHeader() http.Header {
	return http.Header{
		"X-Porta-Address": {"10.66.0.2/29"},
		"X-Porta-Gateway": {"10.66.0.1"},
		"X-Porta-Dns":     {"1.1.1.1"},
		"X-Porta-Mtu":     {"1300"},
	}
}
