package clientip

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
)

func Address(r *http.Request, trustProxyHeaders bool) netip.Addr {
	remote := parseRemoteAddress(r.RemoteAddr)
	if !trustProxyHeaders || !remote.IsValid() || !remote.IsLoopback() {
		return remote
	}
	forwarded := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	for index := len(forwarded) - 1; index >= 0; index-- {
		if address, err := netip.ParseAddr(strings.TrimSpace(forwarded[index])); err == nil {
			return address.Unmap()
		}
	}
	if address, err := netip.ParseAddr(strings.TrimSpace(r.Header.Get("X-Real-IP"))); err == nil {
		return address.Unmap()
	}
	return remote
}

func String(r *http.Request, trustProxyHeaders bool) string {
	if address := Address(r, trustProxyHeaders); address.IsValid() {
		return address.String()
	}
	return r.RemoteAddr
}

func parseRemoteAddress(value string) netip.Addr {
	if address, err := netip.ParseAddrPort(value); err == nil {
		return address.Addr().Unmap()
	}
	host, _, err := net.SplitHostPort(value)
	if err != nil {
		host = value
	}
	address, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	return address.Unmap()
}
