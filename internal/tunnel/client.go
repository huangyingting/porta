package tunnel

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"syscall"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
)

type Transport string

const (
	TransportAuto  Transport = "auto"
	TransportHTTP2 Transport = "h2"
	TransportHTTP3 Transport = "h3"
)

type Config struct {
	URL       string
	Token     string
	ClientID  string
	Transport Transport
	TLSConfig *tls.Config
	Timeout   time.Duration
	// DialAddress pins the physical endpoint while retaining URL's authority
	// and TLS server name. When set it must contain a literal IP and port.
	DialAddress string

	// PacketConn and RemoteAddr allow callers such as Android VPN clients to
	// create and protect the UDP socket before QUIC starts. They must be set
	// together and are only used by HTTP/3 MASQUE. PacketConn remains owned by
	// the caller and is never closed by Conn.
	PacketConn net.PacketConn
	RemoteAddr net.Addr
}

type Lease struct {
	Address netip.Prefix
	Gateway netip.Addr
	DNS     netip.Addr
	MTU     int
}

type DeliveryMode string

const (
	DeliveryModeUnknown  DeliveryMode = ""
	DeliveryModeCapsule  DeliveryMode = "capsule"
	DeliveryModeDatagram DeliveryMode = "datagram"
)

type Conn struct {
	Lease        Lease
	RemoteAddr   net.Addr
	Transport    Transport
	DeliveryMode DeliveryMode
	MTUAutomatic bool
	MTUCeiling   int

	sendPacket    func([]byte) error
	receivePacket func() ([]byte, error)
	closePacket   func() error
	close         sync.Once
}

func Dial(ctx context.Context, config Config) (*Conn, error) {
	if config.Transport == "" || config.Transport == TransportAuto {
		config.Transport = TransportHTTP3
		connection, err := dialTransport(ctx, config)
		if err == nil || !IsTransportUnavailable(err) || ctx.Err() != nil || config.PacketConn != nil {
			return connection, err
		}
		config.Transport = TransportHTTP2
		return dialTransport(ctx, config)
	}
	return dialTransport(ctx, config)
}

func dialTransport(ctx context.Context, config Config) (*Conn, error) {
	connection, err := dialMasque(ctx, config)
	if err == nil {
		connection.Transport = config.Transport
	}
	return connection, err
}

// TransportUnavailableError is reserved for a transport that cannot be reached
// before an HTTP session is established, not a rejected or malformed session.
type TransportUnavailableError struct{ Err error }

func (e TransportUnavailableError) Error() string { return e.Err.Error() }
func (e TransportUnavailableError) Unwrap() error { return e.Err }

// PermanentError prevents retries and downgrade even when its cause is a timeout.
type PermanentError struct{ Err error }

func (e PermanentError) Error() string { return e.Err.Error() }
func (e PermanentError) Unwrap() error { return e.Err }

func IsTransportUnavailable(err error) bool {
	if isPermanent(err) {
		return false
	}
	var response *GatewayResponseError
	if errors.As(err, &response) && !unavailableGatewayResponse(response) {
		return false
	}
	var unavailable TransportUnavailableError
	var unavailablePointer *TransportUnavailableError
	return errors.As(err, &unavailable) || errors.As(err, &unavailablePointer)
}

func isPermanent(err error) bool {
	var permanent PermanentError
	var permanentPointer *PermanentError
	var certificate *tls.CertificateVerificationError
	var unknownAuthority x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var invalidCertificate x509.CertificateInvalidError
	var tlsRecord tls.RecordHeaderError
	var tlsAlert tls.AlertError
	return errors.As(err, &permanent) || errors.As(err, &permanentPointer) || errors.As(err, &certificate) ||
		errors.As(err, &unknownAuthority) || errors.As(err, &hostname) ||
		errors.As(err, &invalidCertificate) || errors.As(err, &tlsRecord) ||
		errors.As(err, &tlsAlert) || isTransportProtocolError(err, false)
}

func normalHTTP3Close(code uint64) bool {
	return code == 0 || code == uint64(http3.ErrCodeNoError) || code == uint64(http3.ErrCodeRequestCanceled)
}

func normalHTTP2StreamClose(code http2.ErrCode) bool {
	return code == http2.ErrCodeNo || code == http2.ErrCodeCancel || code == http2.ErrCodeRefusedStream
}

func retryableGatewayStatus(status int) bool {
	switch status {
	case http.StatusRequestTimeout, http.StatusTooEarly, http.StatusTooManyRequests,
		http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}

func unavailableGatewayResponse(response *GatewayResponseError) bool {
	switch response.StatusCode {
	case http.StatusNotFound, http.StatusMethodNotAllowed, http.StatusMisdirectedRequest,
		http.StatusNotImplemented, http.StatusHTTPVersionNotSupported:
		return true
	case http.StatusUpgradeRequired:
		return response.ServerMinVersion == "" && response.ServerMaxVersion == ""
	default:
		return false
	}
}

func isTransportProtocolError(err error, unavailable bool) bool {
	switch failure := err.(type) {
	case TransportUnavailableError:
		return isTransportProtocolError(failure.Err, true)
	case *TransportUnavailableError:
		return isTransportProtocolError(failure.Err, true)
	case *GatewayResponseError:
		return !retryableGatewayStatus(failure.StatusCode) && !(unavailable && unavailableGatewayResponse(failure))
	case *quic.TransportError:
		return failure.ErrorCode != 0
	case *quic.ApplicationError:
		return !normalHTTP3Close(uint64(failure.ErrorCode))
	case *quic.StreamError:
		return !normalHTTP3Close(uint64(failure.ErrorCode))
	case http2.StreamError:
		return !normalHTTP2StreamClose(failure.Code) || isPermanent(failure.Cause)
	case *http2.StreamError:
		return !normalHTTP2StreamClose(failure.Code) || isPermanent(failure.Cause)
	case http2.GoAwayError:
		return failure.ErrCode != http2.ErrCodeNo
	case *http2.GoAwayError:
		return failure.ErrCode != http2.ErrCodeNo
	case interface{ Unwrap() []error }:
		for _, cause := range failure.Unwrap() {
			if isTransportProtocolError(cause, unavailable) {
				return true
			}
		}
	case interface{ Unwrap() error }:
		return isTransportProtocolError(failure.Unwrap(), unavailable)
	}
	return false
}

func isNormalTransportClose(err error) bool {
	var transport *quic.TransportError
	var application *quic.ApplicationError
	var stream *quic.StreamError
	var http2Stream http2.StreamError
	var http2StreamPointer *http2.StreamError
	var http2GoAway http2.GoAwayError
	var http2GoAwayPointer *http2.GoAwayError
	return errors.As(err, &transport) && transport.ErrorCode == 0 ||
		errors.As(err, &application) && normalHTTP3Close(uint64(application.ErrorCode)) ||
		errors.As(err, &stream) && normalHTTP3Close(uint64(stream.ErrorCode)) ||
		errors.As(err, &http2Stream) && normalHTTP2StreamClose(http2Stream.Code) ||
		errors.As(err, &http2StreamPointer) && normalHTTP2StreamClose(http2StreamPointer.Code) ||
		errors.As(err, &http2GoAway) && http2GoAway.ErrCode == http2.ErrCodeNo ||
		errors.As(err, &http2GoAwayPointer) && http2GoAwayPointer.ErrCode == http2.ErrCodeNo
}

// IsRetryable deliberately defaults to false for unclassified startup failures.
func IsRetryable(err error) bool {
	if err == nil || isPermanent(err) || errors.Is(err, context.Canceled) {
		return false
	}
	if IsTransportUnavailable(err) || isNormalTransportClose(err) || errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, net.ErrClosed) || errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.EPIPE) ||
		errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.EHOSTUNREACH) {
		return true
	}
	var response *GatewayResponseError
	if errors.As(err, &response) {
		return retryableGatewayStatus(response.StatusCode)
	}
	var networkError net.Error
	return errors.As(err, &networkError) && (networkError.Timeout() || networkError.Temporary())
}

func (c *Conn) Send(packet []byte) error {
	return c.sendPacket(packet)
}

func (c *Conn) Receive() ([]byte, error) {
	return c.receivePacket()
}

func (c *Conn) Close() error {
	var result error
	c.close.Do(func() {
		result = c.closePacket()
	})
	return result
}
