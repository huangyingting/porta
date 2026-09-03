package masque

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/quic-go/quic-go/quicvarint"
)

var ErrMalformedAddress = errors.New("malformed MASQUE address entry")

type Address struct {
	RequestID uint64
	Prefix    netip.Prefix
}

func EncodeAddressRequest(addresses []Address) ([]byte, error) {
	if len(addresses) == 0 {
		return nil, errors.New("ADDRESS_REQUEST requires at least one address")
	}
	for _, address := range addresses {
		if address.RequestID == 0 {
			return nil, errors.New("ADDRESS_REQUEST IDs must be non-zero")
		}
	}
	return encodeAddresses(addresses)
}

func DecodeAddressRequest(value []byte) ([]Address, error) {
	addresses, err := decodeAddresses(value)
	if err != nil {
		return nil, err
	}
	if len(addresses) == 0 {
		return nil, errors.New("ADDRESS_REQUEST contained no addresses")
	}
	for _, address := range addresses {
		if address.RequestID == 0 {
			return nil, errors.New("ADDRESS_REQUEST contained request ID zero")
		}
	}
	return addresses, nil
}

func EncodeAddressAssign(addresses []Address) ([]byte, error) {
	return encodeAddresses(addresses)
}

func DecodeAddressAssign(value []byte) ([]Address, error) {
	return decodeAddresses(value)
}

func encodeAddresses(addresses []Address) ([]byte, error) {
	var value []byte
	for _, address := range addresses {
		prefix := address.Prefix
		if !prefix.IsValid() || (prefix.Addr().Is4() && prefix.Bits() > 32) || (prefix.Addr().Is6() && prefix.Bits() > 128) {
			return nil, ErrMalformedAddress
		}
		if prefix.Masked().Addr() != prefix.Addr() {
			return nil, fmt.Errorf("%w: prefix address is not masked", ErrMalformedAddress)
		}
		value = quicvarint.Append(value, address.RequestID)
		if prefix.Addr().Is4() {
			value = append(value, 4)
			bytes := prefix.Addr().As4()
			value = append(value, bytes[:]...)
		} else if prefix.Addr().Is6() {
			value = append(value, 6)
			bytes := prefix.Addr().As16()
			value = append(value, bytes[:]...)
		} else {
			return nil, ErrMalformedAddress
		}
		value = append(value, byte(prefix.Bits()))
	}
	return value, nil
}

func decodeAddresses(value []byte) ([]Address, error) {
	addresses := make([]Address, 0, 1)
	for len(value) > 0 {
		requestID, consumed, err := quicvarint.Parse(value)
		if err != nil {
			return nil, fmt.Errorf("%w: request ID: %v", ErrMalformedAddress, err)
		}
		value = value[consumed:]
		if len(value) < 1 {
			return nil, ErrMalformedAddress
		}
		version := value[0]
		value = value[1:]
		addressLength := 0
		maxBits := 0
		switch version {
		case 4:
			addressLength, maxBits = 4, 32
		case 6:
			addressLength, maxBits = 16, 128
		default:
			return nil, fmt.Errorf("%w: invalid IP version %d", ErrMalformedAddress, version)
		}
		if len(value) < addressLength+1 {
			return nil, ErrMalformedAddress
		}
		var address netip.Addr
		if version == 4 {
			address = netip.AddrFrom4([4]byte(value[:4]))
		} else {
			address = netip.AddrFrom16([16]byte(value[:16]))
		}
		prefixBits := int(value[addressLength])
		value = value[addressLength+1:]
		if prefixBits > maxBits {
			return nil, fmt.Errorf("%w: invalid prefix length %d", ErrMalformedAddress, prefixBits)
		}
		prefix := netip.PrefixFrom(address, prefixBits)
		if prefix.Masked().Addr() != address {
			return nil, fmt.Errorf("%w: prefix address is not masked", ErrMalformedAddress)
		}
		addresses = append(addresses, Address{RequestID: requestID, Prefix: prefix})
	}
	return addresses, nil
}
