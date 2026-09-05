package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/huangyingting/porta/internal/buildinfo"
	"github.com/huangyingting/porta/internal/clientapp"
	"github.com/huangyingting/porta/internal/tunnel"
)

func main() {
	if buildinfo.IsVersionRequest(os.Args[1:]) {
		fmt.Println(buildinfo.Version)
		return
	}
	if err := run(); err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintln(os.Stderr, "porta-client:", err)
		os.Exit(1)
	}
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if handled, err := runNetworkHelper(ctx, os.Args[1:]); handled {
		return err
	}
	serverURL := flag.String("server", "", "gateway origin, for example https://vpn.example.com:8443")
	transportName := flag.String("transport", "auto", "tunnel transport: auto (HTTP/3 with safe HTTP/2 fallback), h3, or h2")
	interfaceName := flag.String("interface", defaultInterfaceName(), "TUN interface name")
	caPath := flag.String("ca", "", "optional PEM CA certificate")
	thumbprint := flag.String("thumbprint", "", "optional SHA-256 gateway certificate thumbprint")
	insecure := flag.Bool("insecure", false, "skip TLS certificate verification (development only)")
	tokenFlag := flag.String("token", "", "bearer token (prefer PORTA_TOKEN environment variable)")
	reconnect := flag.Bool("reconnect", true, "retry transient startup failures and interrupted tunnels")
	reconnectMaxDelay := flag.Duration("reconnect-max-delay", 30*time.Second, "maximum reconnect delay")
	manualNetwork := flag.Bool("manual-network", runtime.GOOS != "linux", "manage routes, DNS, and leak protection yourself (Linux defaults to automatic)")
	cleanupNetwork := flag.Bool("cleanup-network", false, "restore network and remove Porta's crash-surviving guard, then exit")
	networkState := flag.String("network-state", "", "network recovery state file (default: platform-specific Porta state)")
	flag.Parse()

	token := os.Getenv("PORTA_TOKEN")
	if token == "" {
		token = *tokenFlag
	}
	var network clientapp.NetworkConfigurator
	if *cleanupNetwork || !*manualNetwork {
		var err error
		network, err = newNetworkConfigurator(*networkState)
		if err != nil {
			return err
		}
	}
	if *cleanupNetwork {
		cleanupCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		return network.Down(cleanupCtx)
	}
	return clientapp.Run(ctx, clientapp.Config{
		ServerURL:         *serverURL,
		Token:             token,
		Transport:         tunnel.Transport(*transportName),
		InterfaceName:     *interfaceName,
		CAPath:            *caPath,
		Thumbprint:        *thumbprint,
		Insecure:          *insecure,
		Reconnect:         *reconnect,
		ReconnectMaxDelay: *reconnectMaxDelay,
		Network:           network,
	}, func(event clientapp.Event) {
		if event.State == clientapp.StateConnected {
			fmt.Fprintf(os.Stderr, "porta-client: connected address=%s dns=%s mtu=%d transport=%s uploaded=%d downloaded=%d\n",
				event.Lease.Address, event.Lease.DNS, event.Lease.MTU, event.Transport, event.BytesUploaded, event.BytesDownloaded)
		} else {
			fmt.Fprintf(os.Stderr, "porta-client: %s\n", event.Message)
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
