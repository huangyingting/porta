package tunnel

import (
	"context"
	"fmt"
	"net/http"
	"strconv"

	"github.com/huangyingting/porta/internal/masque"
)

type clientMTUDiscovery struct {
	token    masque.MTUToken
	maximum  int
	echoes   chan masque.MTUProbe
	selected chan int
}

func (m *masqueClient) configureMTU(header http.Header) error {
	offer := header.Get(masque.MTUDiscoveryHeader)
	if offer == "" {
		return nil
	}
	token, err := masque.ParseMTUToken(offer)
	maximum, mtuErr := strconv.Atoi(header.Get("X-Porta-MTU"))
	if err != nil || mtuErr != nil || maximum <= masque.SafeMTU || maximum > 9000 ||
		m.sendDatagram == nil || m.receiveDatagram == nil {
		return PermanentError{Err: fmt.Errorf("%w: unsupported gateway MTU offer", masque.ErrMTUMessage)}
	}
	m.mtuDiscovery = &clientMTUDiscovery{
		token: token, maximum: min(maximum, masque.MaxDiscoveredMTU),
		echoes: make(chan masque.MTUProbe, 16), selected: make(chan int, 1),
	}
	return nil
}

func (m *masqueClient) selectMTU(ctx context.Context) error {
	if m.mtuDiscovery == nil {
		return nil
	}
	p := m.mtuDiscovery
	mtu, err := masque.DiscoverMTU(ctx, p.maximum, p.token, m.sendDatagram, p.echoes, m.errors)
	if err != nil {
		return err
	}
	if err := m.encoder.Write(masque.CapsuleMTUSelect, masque.EncodeMTUSelection(p.token, mtu)); err != nil {
		return err
	}
	m.encoder.Flush()
	select {
	case selected := <-p.selected:
		if selected != mtu {
			return PermanentError{Err: fmt.Errorf("%w: gateway selected %d instead of %d", masque.ErrMTUMessage, selected, mtu)}
		}
		m.lease.MTU = selected
		return nil
	case err := <-m.errors:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}
