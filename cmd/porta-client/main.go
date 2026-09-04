package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/huangyingting/porta/internal/clientapp"
	"github.com/huangyingting/porta/internal/tunnel"
)

var invalidClientID = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

func main() {
	if err := run(); err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintln(os.Stderr, "porta-client:", err)
		os.Exit(1)
	}
}

func run() error {
	serverURL := flag.String("server", "", "gateway origin, for example https://vpn.example.com:8443")
	transportName := flag.String("transport", "h3", "tunnel transport: h3 or h2")
	interfaceName := flag.String("interface", defaultInterfaceName(), "TUN interface name")
	clientID := flag.String("client-id", defaultClientID(), "stable client identifier")
	caPath := flag.String("ca", "", "optional PEM CA certificate")
	thumbprint := flag.String("thumbprint", "", "optional SHA-256 gateway certificate thumbprint")
	insecure := flag.Bool("insecure", false, "skip TLS certificate verification (development only)")
	tokenFlag := flag.String("token", "", "bearer token (prefer PORTA_TOKEN environment variable)")
	reconnect := flag.Bool("reconnect", true, "reconnect automatically after an established tunnel is interrupted")
	reconnectMaxDelay := flag.Duration("reconnect-max-delay", 30*time.Second, "maximum reconnect delay")
	flag.Parse()

	token := os.Getenv("PORTA_TOKEN")
	if token == "" {
		token = *tokenFlag
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	return clientapp.Run(ctx, clientapp.Config{
		ServerURL:         *serverURL,
		Token:             token,
		ClientID:          *clientID,
		Transport:         tunnel.Transport(*transportName),
		InterfaceName:     *interfaceName,
		CAPath:            *caPath,
		Thumbprint:        *thumbprint,
		Insecure:          *insecure,
		Reconnect:         *reconnect,
		ReconnectMaxDelay: *reconnectMaxDelay,
	}, func(event clientapp.Event) {
		if event.State == clientapp.StateConnected {
			fmt.Fprintf(os.Stderr, "porta-client: connected address=%s transport=%s uploaded=%d downloaded=%d\n",
				event.Lease.Address, event.Transport, event.BytesUploaded, event.BytesDownloaded)
		}
	})
}

func reconnectDelay(failures int, maximum time.Duration) time.Duration {
	return clientapp.ReconnectDelay(failures, maximum)
}

func clientTLSConfig(caPath, thumbprint string, insecure bool) (*tls.Config, error) {
	return clientapp.TLSConfig(caPath, thumbprint, insecure)
}

func parseThumbprint(value string) ([]byte, error) {
	return clientapp.ParseThumbprint(value)
}

func defaultInterfaceName() string {
	if runtime.GOOS == "windows" {
		return "Porta"
	}
	return "porta0"
}

func defaultClientID() string {
	hostname, err := os.Hostname()
	if err != nil || hostname == "" {
		return "porta-client"
	}
	value := strings.Trim(invalidClientID.ReplaceAllString(hostname, "-"), "-._")
	if value == "" {
		return "porta-client"
	}
	if len(value) > 64 {
		value = value[:64]
	}
	return value
}
