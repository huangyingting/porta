package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/htun-project/htun/internal/device"
	"github.com/htun-project/htun/internal/gateway"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
)

func main() {
	if err := ensureExtendedConnect(); err != nil {
		fmt.Fprintln(os.Stderr, "htun-server:", err)
		os.Exit(1)
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "htun-server:", err)
		os.Exit(1)
	}
}

func ensureExtendedConnect() error {
	if strings.Contains(os.Getenv("GODEBUG"), "http2xconnect=1") {
		return nil
	}
	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate server executable: %w", err)
	}
	environment := os.Environ()
	updated := false
	for index, entry := range environment {
		if !strings.HasPrefix(entry, "GODEBUG=") {
			continue
		}
		value := strings.TrimPrefix(entry, "GODEBUG=")
		if value != "" {
			value += ","
		}
		environment[index] = "GODEBUG=" + value + "http2xconnect=1"
		updated = true
		break
	}
	if !updated {
		environment = append(environment, "GODEBUG=http2xconnect=1")
	}
	return syscall.Exec(executable, os.Args, environment)
}

func run() error {
	address := flag.String("listen", ":8443", "TCP and UDP listen address")
	certPath := flag.String("cert", "server.crt", "TLS certificate path")
	keyPath := flag.String("key", "server.key", "TLS private-key path")
	interfaceName := flag.String("interface", "htun0", "Linux TUN interface name")
	poolCIDR := flag.String("pool", "10.66.0.0/24", "IPv4 client address pool")
	dns := flag.String("dns", "1.1.1.1", "DNS address advertised to clients")
	mtu := flag.Int("mtu", 1300, "tunnel MTU")
	tokenFlag := flag.String("token", "", "bearer token (prefer HTUN_TOKEN environment variable)")
	jsonLogs := flag.Bool("json-logs", false, "write structured JSON logs")
	flag.Parse()

	token := os.Getenv("HTUN_TOKEN")
	if token == "" {
		token = *tokenFlag
	}
	if len(token) < 16 {
		return errors.New("set HTUN_TOKEN to a random value of at least 16 characters")
	}

	var logHandler slog.Handler
	if *jsonLogs {
		logHandler = slog.NewJSONHandler(os.Stderr, nil)
	} else {
		logHandler = slog.NewTextHandler(os.Stderr, nil)
	}
	logger := slog.New(logHandler)

	pool, err := gateway.NewPool(*poolCIDR)
	if err != nil {
		return err
	}
	tunDevice, err := device.OpenNative(*interfaceName, *mtu)
	if err != nil {
		return err
	}
	defer tunDevice.Close()

	router := gateway.NewRouter(tunDevice, logger)
	handler, err := gateway.NewHandler(gateway.HandlerConfig{
		Token:             token,
		Pool:              pool,
		Router:            router,
		DNS:               *dns,
		MTU:               *mtu,
		EnableH3Datagrams: true,
		Logger:            logger,
	})
	if err != nil {
		return err
	}

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2", "http/1.1"},
	}
	tcpServer := &http.Server{
		Addr:              *address,
		Handler:           handler,
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	if err := http2.ConfigureServer(tcpServer, &http2.Server{}); err != nil {
		return fmt.Errorf("configure HTTP/2: %w", err)
	}
	quicServer := &http3.Server{
		Addr:            *address,
		Handler:         handler,
		EnableDatagrams: true,
		MaxHeaderBytes:  16 << 10,
		IdleTimeout:     90 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errCh := make(chan error, 3)
	go func() { errCh <- router.Run(ctx) }()
	go func() { errCh <- tcpServer.ListenAndServeTLS(*certPath, *keyPath) }()
	go func() { errCh <- quicServer.ListenAndServeTLS(*certPath, *keyPath) }()

	logger.Info("gateway ready",
		"listen", *address,
		"interface", tunDevice.Name(),
		"pool", *poolCIDR,
		"gateway", pool.Gateway(),
		"transports", "h2,h3",
	)

	select {
	case <-ctx.Done():
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			stop()
			return err
		}
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = quicServer.Shutdown(shutdownCtx)
	_ = tcpServer.Shutdown(shutdownCtx)
	return nil
}
