package winnetwork

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
)

func validJournalGUID(value string) bool {
	if len(value) == 38 && value[0] == '{' && value[37] == '}' {
		value = value[1:37]
	}
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	_, err := hex.DecodeString(strings.ReplaceAll(value, "-", ""))
	return err == nil
}

func (s networkState) validate() error {
	if s.Version != exactOwnershipStateVersion && s.Version != nativeMTUStateVersion {
		return fmt.Errorf("unsupported version %d; restore older journals with the client that created them", s.Version)
	}
	if strings.TrimSpace(s.Interface) == "" || strings.ContainsRune(s.Interface, 0) || !validJournalGUID(s.GuardKey) {
		return errors.New("missing interface or guard ownership")
	}
	address := net.TCPAddrFromAddrPort(netip.AddrPortFrom(s.Endpoint.IP, s.Endpoint.Port))
	endpoint, err := parseEndpoint(address)
	if err != nil || endpoint != s.Endpoint || s.ServerIP != s.Endpoint.IP.String() {
		return errors.New("invalid pinned endpoint")
	}
	if s.InterfaceLUID != 0 && !validJournalGUID(s.InterfaceGUID) {
		return errors.New("missing tunnel adapter identity")
	}
	for _, route := range s.Routes {
		prefix, err := netip.ParsePrefix(route.Prefix)
		nextHop, hopErr := netip.ParseAddr(route.NextHop)
		if err != nil || hopErr != nil || nextHop.Is4() != prefix.Addr().Is4() || route.Interface <= 0 || !validJournalGUID(route.GUID) || route.Metric < 0 {
			return errors.New("invalid route ownership")
		}
		switch route.Kind {
		case "tunnel":
			if route.Prefix != "0.0.0.0/1" && route.Prefix != "128.0.0.0/1" {
				return errors.New("invalid tunnel route")
			}
		case "dns", "escape":
			if prefix.Bits() != prefix.Addr().BitLen() || (route.Kind == "dns" && !prefix.Addr().Is4()) {
				return errors.New("invalid owned host route")
			}
		default:
			return errors.New("missing route kind")
		}
	}
	for _, address := range s.Addresses {
		prefix, err := netip.ParsePrefix(address)
		if err != nil || !prefix.Addr().Is4() || !prefix.Addr().IsGlobalUnicast() {
			return errors.New("invalid owned address")
		}
	}
	if s.MTU != nil {
		if s.MTU.Original == 0 || !optionalMTU(s.MTU.Applied) || !optionalMTU(s.MTU.Pending) {
			return errors.New("invalid MTU recovery state")
		}
	}
	if s.DNS != nil {
		for _, value := range []string{s.DNS.Applied, s.DNS.Pending} {
			if value == "" {
				continue
			}
			address, err := netip.ParseAddr(value)
			if err != nil || !address.Is4() || !address.IsGlobalUnicast() {
				return errors.New("invalid DNS recovery state")
			}
		}
	}
	return nil
}

func optionalMTU(value int) bool { return value == 0 || value >= 576 && value <= 9000 }
