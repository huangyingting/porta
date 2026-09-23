package masque

import (
	"context"

	"github.com/quic-go/quic-go"
)

type connectionKey struct{}

func ConnContext(ctx context.Context, conn *quic.Conn) context.Context {
	return context.WithValue(ctx, connectionKey{}, conn)
}

func Connection(ctx context.Context) *quic.Conn {
	conn, _ := ctx.Value(connectionKey{}).(*quic.Conn)
	return conn
}
