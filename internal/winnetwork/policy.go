package winnetwork

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"strconv"
)

type endpoint struct {
	IP   netip.Addr `json:"ip"`
	Port uint16     `json:"port"`
}

func parseEndpoint(addr net.Addr) (endpoint, error) {
	if addr == nil {
		return endpoint{}, fmt.Errorf("tunnel did not report its remote address")
	}
	host, port, err := net.SplitHostPort(addr.String())
	if err != nil {
		return endpoint{}, fmt.Errorf("tunnel remote address is invalid: %w", err)
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || ip.Zone() != "" || !ip.IsGlobalUnicast() {
		return endpoint{}, fmt.Errorf("tunnel endpoint must be an unscoped unicast IP address")
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil || p == 0 {
		return endpoint{}, fmt.Errorf("tunnel endpoint port is invalid")
	}
	if p == 53 || p == 853 {
		return endpoint{}, fmt.Errorf("DNS ports 53 and 853 cannot be exempted for the tunnel transport")
	}
	return endpoint{IP: ip.Unmap(), Port: uint16(p)}, nil
}

type guardSpec struct {
	Key           string
	InterfaceLUID uint64
	Endpoint      endpoint
	Application   string
}

type condition struct {
	field string
	value any
}

type filter struct {
	layer      string
	permit     bool
	conditions []condition
}

// Permits are soft and are evaluated before the final block IN OUR OWN WFP
// SUBLAYER. They do not override another sublayer's blocks. This is deliberately
// not Windows Firewall's "block everything plus allow exceptions" rule model.
// See https://learn.microsoft.com/windows/win32/fwp/filter-arbitration.
func guardFilters(spec guardSpec) []filter {
	var filters []filter
	add := func(layer string, conditions ...condition) {
		filters = append(filters, filter{layer: layer, permit: true, conditions: conditions})
	}
	for _, family := range []string{"4", "6"} {
		// Both ALE directions must change to reauthorize existing inbound
		// AND outbound flows. Packet/transport filters also constrain traffic
		// independently of cached ALE authorization.
		// https://learn.microsoft.com/windows/win32/fwp/ale-re-authorization
		for _, kind := range []string{"packet", "transport", "connect", "accept"} {
			layer := kind + family
			add(layer, condition{"loopback", true})
			if family == "4" && spec.InterfaceLUID != 0 {
				add(layer, condition{"interface", spec.InterfaceLUID})
			}
			if (family == "4") == spec.Endpoint.IP.Is4() {
				if kind == "packet" {
					add(layer, condition{"address", netip.PrefixFrom(spec.Endpoint.IP, spec.Endpoint.IP.BitLen())})
				} else {
					for _, protocol := range []uint8{6, 17} {
						conditions := []condition{
							{"address", netip.PrefixFrom(spec.Endpoint.IP, spec.Endpoint.IP.BitLen())},
							{"protocol", protocol}, {"port", spec.Endpoint.Port},
						}
						if kind == "connect" || kind == "accept" {
							conditions = append(conditions, condition{"application", spec.Application})
						}
						add(layer, conditions...)
					}
				}
			}
			// IPv6 transport needs neighbor discovery even though IPv6 payload
			// is unsupported. The packet-layer address exceptions are narrowed
			// to ICMPv6 RS/NS/NA, code zero, at the transport and ALE layers.
			if family == "6" && spec.Endpoint.IP.Is6() {
				for _, prefix := range []string{"fe80::/10", "ff02::/16"} {
					address := condition{"address", netip.MustParsePrefix(prefix)}
					if kind == "packet" {
						add(layer, address)
					} else {
						types := []uint16{133, 135, 136}
						if kind == "accept" {
							types = append(types, 134) // Receive router advertisements; never send them.
						}
						for _, icmpType := range types {
							add(layer, address, condition{"protocol", uint8(58)}, condition{"local-port", icmpType}, condition{"port", uint16(0)})
						}
					}
				}
			}
			filters = append(filters, filter{layer: layer})
		}
		// Forwarded traffic has no trustworthy application identity.
		filters = append(filters, filter{layer: "forward" + family})
	}
	return filters
}

// Stable keys make a crash between journal persistence and a WFP transaction
// recoverable, without enumerating or deleting any other application's objects.
func objectKey(owner string, index int) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("Porta full tunnel v1:%s:%d", owner, index)))
	sum[6] = (sum[6] & 0x0f) | 0x50
	sum[8] = (sum[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		binary.BigEndian.Uint32(sum[:4]), binary.BigEndian.Uint16(sum[4:6]),
		binary.BigEndian.Uint16(sum[6:8]), binary.BigEndian.Uint16(sum[8:10]), sum[10:16])
}

const maxGuardFilters = 128
