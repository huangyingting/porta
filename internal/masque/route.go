package masque

import (
	"errors"
	"fmt"
	"net/netip"
)

var ErrMalformedRoute = errors.New("malformed MASQUE route")

type Route struct {
	Start    netip.Addr
	End      netip.Addr
	Protocol uint8
}

func EncodeRouteAdvertisement(routes []Route) ([]byte, error) {
	var value []byte
	for index, route := range routes {
		if !route.Start.IsValid() || !route.End.IsValid() || route.Start.BitLen() != route.End.BitLen() || route.Start.Compare(route.End) > 0 {
			return nil, ErrMalformedRoute
		}
		if index > 0 && compareRoutes(routes[index-1], route) >= 0 {
			return nil, errors.New("MASQUE routes must be ordered and non-overlapping")
		}
		if route.Start.Is4() {
			value = append(value, 4)
			start, end := route.Start.As4(), route.End.As4()
			value = append(value, start[:]...)
			value = append(value, end[:]...)
		} else {
			value = append(value, 6)
			start, end := route.Start.As16(), route.End.As16()
			value = append(value, start[:]...)
			value = append(value, end[:]...)
		}
		value = append(value, route.Protocol)
	}
	return value, nil
}

func DecodeRouteAdvertisement(value []byte) ([]Route, error) {
	routes := make([]Route, 0, 1)
	for len(value) > 0 {
		version := value[0]
		value = value[1:]
		addressLength := 0
		switch version {
		case 4:
			addressLength = 4
		case 6:
			addressLength = 16
		default:
			return nil, fmt.Errorf("%w: invalid IP version %d", ErrMalformedRoute, version)
		}
		if len(value) < addressLength*2+1 {
			return nil, ErrMalformedRoute
		}
		var start, end netip.Addr
		if version == 4 {
			start = netip.AddrFrom4([4]byte(value[:4]))
			end = netip.AddrFrom4([4]byte(value[4:8]))
		} else {
			start = netip.AddrFrom16([16]byte(value[:16]))
			end = netip.AddrFrom16([16]byte(value[16:32]))
		}
		protocol := value[addressLength*2]
		value = value[addressLength*2+1:]
		route := Route{Start: start, End: end, Protocol: protocol}
		if start.Compare(end) > 0 {
			return nil, ErrMalformedRoute
		}
		if len(routes) > 0 && compareRoutes(routes[len(routes)-1], route) >= 0 {
			return nil, errors.New("MASQUE routes are unordered or overlapping")
		}
		routes = append(routes, route)
	}
	return routes, nil
}

func compareRoutes(a, b Route) int {
	if a.Start.BitLen() != b.Start.BitLen() {
		if a.Start.Is4() {
			return -1
		}
		return 1
	}
	if a.Protocol != b.Protocol {
		if a.Protocol < b.Protocol {
			return -1
		}
		return 1
	}
	if a.End.Compare(b.Start) < 0 {
		return -1
	}
	return 1
}
