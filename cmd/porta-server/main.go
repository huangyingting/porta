package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/huangyingting/porta/internal/buildinfo"
	"github.com/huangyingting/porta/internal/device"
	"github.com/huangyingting/porta/internal/forwardproxy"
	"github.com/huangyingting/porta/internal/gateway"
	"github.com/huangyingting/porta/internal/usage"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

func main() {
	if buildinfo.IsVersionRequest(os.Args[1:]) {
		fmt.Println(buildinfo.Version)
		return
	}
	if err := ensureExtendedConnect(); err != nil {
		fmt.Fprintln(os.Stderr, "porta-server:", err)
		os.Exit(1)
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "porta-server:", err)
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
	address := flag.String("listen", ":8443", "listen address (TCP and UDP normally, TCP only behind a proxy)")
	acmeDomain := flag.String("acme-domain", "", "domain for automatic Let's Encrypt certificates (required unless using --behind-proxy or static TLS)")
	acmeEmail := flag.String("acme-email", "", "contact email for Let's Encrypt")
	acmeCache := flag.String("acme-cache", "acme-cache", "Let's Encrypt certificate cache directory")
	acmeHTTPAddress := flag.String("acme-http-listen", ":80", "HTTP-01 challenge listen address (empty uses TLS-ALPN-01)")
	tlsCert := flag.String("tls-cert", "", "static TLS certificate file (reloaded when replaced)")
	tlsKey := flag.String("tls-key", "", "static TLS private key file (reloaded when replaced)")
	behindProxy := flag.Bool("behind-proxy", false, "serve plaintext HTTP/2 for a TLS-terminating reverse proxy (disables ACME and HTTP/3)")
	landingPage := flag.Bool("landing-page", true, "serve the Porta landing page to ordinary browser requests")
	disableForwardProxy := flag.Bool("disable-forward-proxy", false, "disable the authenticated HTTPS CONNECT proxy on the public listener")
	clientDownloads := flag.String("client-downloads", "", "absolute directory containing published client release artifacts (empty disables downloads)")
	adminAddress := flag.String("admin-listen", "127.0.0.1:9090", "loopback address for the admin UI, health, readiness, and metrics (empty disables)")
	clientRegistryPath := flag.String("client-registry", "clients.json", "persistent client registry path")
	usageStatePath := flag.String("usage-state", "", "persistent client usage state path (defaults beside the client registry)")
	interfaceName := flag.String("interface", "porta0", "Linux TUN interface name")
	poolCIDR := flag.String("pool", "10.66.0.0/24", "IPv4 client address pool")
	leaseState := flag.String("lease-state", "", "optional persistent client lease state file")
	dns := flag.String("dns", "1.1.1.1", "DNS address advertised to clients")
	mtu := flag.Int("mtu", 1400, "tunnel MTU ceiling (fixed MTU with --auto-mtu=false)")
	autoMTU := flag.Bool("auto-mtu", true, "select a stable per-connection HTTP/3 MTU using bounded datagram probes")
	tokenFlag := flag.String("token", "", "bearer token (prefer PORTA_TOKEN environment variable)")
	metricsTokenFlag := flag.String("metrics-token", "", "metrics bearer token (prefer PORTA_METRICS_TOKEN environment variable; empty disables /metrics)")
	jsonLogs := flag.Bool("json-logs", false, "write structured JSON logs")
	egressInterface := flag.String("egress-interface", "", "expected forwarding egress interface (empty discovers a usable default route)")
	readinessTimeout := flag.Duration("readiness-timeout", 3*time.Second, "maximum duration of a readiness check")
	readinessNAT := flag.Bool("readiness-require-nat", true, "require the deployed Porta nftables masquerade rule (disable only for routed deployments)")
	readinessEgressURL := flag.String("readiness-egress-url", "", "optional HTTP(S) egress probe URL; failures do not gate local readiness")
	readinessDNSName := flag.String("readiness-dns-name", "", "optional name to resolve through --dns; failures do not gate local readiness")
	flag.Parse()

	token := os.Getenv("PORTA_TOKEN")
	if token == "" {
		token = *tokenFlag
	}
	if token != "" && len(token) < 16 {
		return errors.New("PORTA_TOKEN must contain at least 16 characters")
	}
	registry, err := openClientRegistry(*clientRegistryPath, token)
	if err != nil {
		return err
	}
	metricsToken := os.Getenv("PORTA_METRICS_TOKEN")
	if metricsToken == "" {
		metricsToken = *metricsTokenFlag
	}
	if metricsToken != "" && len(metricsToken) < 16 {
		return errors.New("PORTA_METRICS_TOKEN must contain at least 16 characters")
	}
	adminToken := os.Getenv("PORTA_ADMIN_TOKEN")
	if adminToken != "" && len(adminToken) < 24 {
		return errors.New("PORTA_ADMIN_TOKEN must contain at least 24 characters")
	}
	if *adminAddress != "" && adminToken == "" {
		return errors.New("PORTA_ADMIN_TOKEN is required when the admin listener is enabled")
	}
	if *adminAddress != "" {
		if err := validateLoopbackListenAddress(*adminAddress, "--admin-listen"); err != nil {
			return err
		}
	}
	if *clientDownloads != "" {
		if !filepath.IsAbs(*clientDownloads) {
			return errors.New("--client-downloads must be an absolute path")
		}
		info, err := os.Stat(*clientDownloads)
		if err != nil {
			return fmt.Errorf("open client downloads directory: %w", err)
		}
		if !info.IsDir() {
			return errors.New("--client-downloads must name a directory")
		}
	}

	var logHandler slog.Handler
	if *jsonLogs {
		logHandler = slog.NewJSONHandler(os.Stderr, nil)
	} else {
		logHandler = slog.NewTextHandler(os.Stderr, nil)
	}
	logger := slog.New(logHandler)
	if *usageStatePath == "" {
		*usageStatePath = filepath.Join(filepath.Dir(*clientRegistryPath), "usage.json")
	}
	usageStore, err := usage.Open(*usageStatePath, logger)
	if err != nil {
		return err
	}

	var (
		tlsConfig          *tls.Config
		certificateManager *autocert.Manager
	)
	if *behindProxy {
		if normalizeDomain(*acmeDomain) != "" || strings.TrimSpace(*acmeEmail) != "" || *tlsCert != "" || *tlsKey != "" {
			return errors.New("--behind-proxy cannot be combined with ACME or static TLS options")
		}
		if err := validateProxyListenAddress(*address); err != nil {
			return err
		}
	} else if *tlsCert != "" || *tlsKey != "" {
		if normalizeDomain(*acmeDomain) != "" || strings.TrimSpace(*acmeEmail) != "" {
			return errors.New("static TLS cannot be combined with --acme-domain or --acme-email")
		}
		tlsConfig, err = staticTLSConfig(*tlsCert, *tlsKey, logger)
		if err != nil {
			return err
		}
	} else {
		tlsConfig, certificateManager, err = serverTLSConfig(*acmeDomain, *acmeEmail, *acmeCache)
		if err != nil {
			return err
		}
	}
	var pool *gateway.Pool
	if *leaseState == "" {
		pool, err = gateway.NewPool(*poolCIDR)
	} else {
		pool, err = gateway.NewPersistentPool(*poolCIDR, *leaseState)
	}
	if err != nil {
		return err
	}
	readiness, err := newForwardingReadiness(forwardingReadinessConfig{
		Interface: *interfaceName, Gateway: pool.Gateway(), Pool: netip.MustParsePrefix(*poolCIDR).Masked(),
		EgressInterface: *egressInterface, RequireNAT: *readinessNAT, Timeout: *readinessTimeout,
		AutoMTU:   *autoMTU,
		EgressURL: *readinessEgressURL, DNSName: *readinessDNSName, DNSAddress: *dns,
	}, localReadinessDependencies())
	if err != nil {
		return err
	}
	tunDevice, err := device.OpenNative(*interfaceName, *mtu)
	if err != nil {
		return err
	}
	defer tunDevice.Close()

	router := gateway.NewRouter(tunDevice, logger)
	metrics := &gateway.Metrics{}
	handler, err := gateway.NewHandler(gateway.HandlerConfig{
		AuthorizeSession:  registry.AuthenticateDeviceSession,
		MetricsToken:      metricsToken,
		Metrics:           metrics,
		Usage:             usageStore,
		Pool:              pool,
		Router:            router,
		DNS:               *dns,
		MTU:               *mtu,
		AutoMTU:           *autoMTU,
		EnableH3Datagrams: true,
		TrustProxyHeaders: *behindProxy,
		Logger:            logger,
		Readiness:         readiness,
	})
	if err != nil {
		return err
	}
	publicHandler := publicSiteHandler(handler, *landingPage)
	publicHandler, err = newPortalHandler(portalConfig{
		Next:               publicHandler,
		Registry:           registry,
		AdminToken:         adminToken,
		Admin:              adminHandlerWithUsage(http.NotFoundHandler(), registry, usageStore, adminToken),
		DownloadsDirectory: *clientDownloads,
		TrustProxyHeaders:  *behindProxy,
		Logger:             logger,
	})
	if err != nil {
		return err
	}
	if !*disableForwardProxy {
		proxyHandler, err := forwardproxy.New(forwardproxy.Config{
			Next: publicHandler,
			AuthorizeSession: func(ctx context.Context, token, _ string) (forwardproxy.Identity, context.Context, func(), error) {
				identity, sessionCtx, release, authorizeErr := registry.AuthenticateProxySession(ctx, token)
				return forwardproxy.Identity{
					AccountID: identity.AccountID,
					DeviceID:  forwardproxy.DeviceID,
				}, sessionCtx, release, authorizeErr
			},
			Logger:     logger,
			Camouflage: true,
			Usage:      usageStore,
		})
		if err != nil {
			return err
		}
		publicHandler = proxyHandler
	}

	draining := newDrainingHandler(publicHandler)
	defer draining.stop()
	publicHandler = draining
	tcpHandler := publicHandler
	if *behindProxy {
		tcpHandler = proxyBackendHandler(publicHandler)
	}
	tcpServer := &http.Server{
		Addr:              *address,
		Handler:           tcpHandler,
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	if !*behindProxy {
		if err := http2.ConfigureServer(tcpServer, &http2.Server{}); err != nil {
			return fmt.Errorf("configure HTTP/2: %w", err)
		}
	}
	var quicServer *http3.Server
	if !*behindProxy {
		quicServer = &http3.Server{
			Addr:            *address,
			Handler:         publicHandler,
			TLSConfig:       http3TLSConfig(tlsConfig),
			EnableDatagrams: true,
			MaxHeaderBytes:  16 << 10,
			IdleTimeout:     90 * time.Second,
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	usageCtx, stopUsage := context.WithCancel(context.Background())
	defer stopUsage()
	usageDone := make(chan struct{})
	go func() {
		defer close(usageDone)
		usageStore.Run(usageCtx, 30*time.Second)
	}()
	tcpServer.BaseContext = func(net.Listener) context.Context { return ctx }
	var acmeHTTPServer *http.Server
	var adminServer *http.Server
	if certificateManager != nil && *acmeHTTPAddress != "" {
		acmeHTTPServer = &http.Server{
			Addr:              *acmeHTTPAddress,
			Handler:           certificateManager.HTTPHandler(nil),
			ReadHeaderTimeout: 10 * time.Second,
			IdleTimeout:       30 * time.Second,
		}
	}
	if *adminAddress != "" {
		adminServer = &http.Server{
			Addr:              *adminAddress,
			Handler:           adminHandlerWithUsage(handler, registry, usageStore, adminToken),
			ReadHeaderTimeout: 5 * time.Second,
			IdleTimeout:       30 * time.Second,
		}
	}

	errCh := make(chan error, 5)
	go func() { errCh <- router.Run(ctx) }()
	if *behindProxy {
		go func() { errCh <- tcpServer.ListenAndServe() }()
	} else {
		go func() { errCh <- tcpServer.ListenAndServeTLS("", "") }()
		go func() { errCh <- quicServer.ListenAndServe() }()
	}
	if acmeHTTPServer != nil {
		go func() { errCh <- acmeHTTPServer.ListenAndServe() }()
	}
	if adminServer != nil {
		go func() { errCh <- adminServer.ListenAndServe() }()
	}

	attributes := []any{
		"listen", *address,
		"interface", tunDevice.Name(),
		"pool", *poolCIDR,
		"gateway", pool.Gateway(),
		"admin_listen", *adminAddress,
	}
	if *behindProxy {
		attributes = append(attributes, "transports", "h2c", "tls", "reverse-proxy")
	} else {
		attributes = append(attributes, "transports", "h2,h3", "acme_domain", normalizeDomain(*acmeDomain))
		if *acmeHTTPAddress != "" {
			attributes = append(attributes, "acme_http_listen", *acmeHTTPAddress)
		}
	}
	attributes = append(attributes, "version", buildinfo.Version)
	logger.Info("gateway listeners starting; forwarding readiness is reported by /readyz", attributes...)

	var runErr error
	select {
	case <-ctx.Done():
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			runErr = err
		}
	}
	draining.stop()
	stop()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	servers := []shutdownServer{tcpServer}
	if quicServer != nil {
		servers = append(servers, quicServer)
	}
	if acmeHTTPServer != nil {
		servers = append(servers, acmeHTTPServer)
	}
	if adminServer != nil {
		servers = append(servers, adminServer)
	}
	shutdownServers(shutdownCtx, servers...)
	if err := draining.wait(shutdownCtx); err != nil {
		logger.Warn("handlers still active during shutdown", "error", err)
	}
	stopUsage()
	<-usageDone
	return runErr
}

func serverTLSConfig(acmeDomain, acmeEmail, acmeCache string) (*tls.Config, *autocert.Manager, error) {
	domain := normalizeDomain(acmeDomain)
	if domain == "" || !strings.Contains(domain, ".") || strings.ContainsAny(domain, "/:") {
		return nil, nil, errors.New("--acme-domain is required and must be a fully qualified DNS name without a scheme or port")
	}
	if acmeCache == "" {
		return nil, nil, errors.New("--acme-cache must not be empty when --acme-domain is set")
	}
	manager := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      autocert.DirCache(acmeCache),
		Email:      strings.TrimSpace(acmeEmail),
		HostPolicy: autocert.HostWhitelist(domain),
	}
	config := manager.TLSConfig()
	config.MinVersion = tls.VersionTLS12
	return config, manager, nil
}

func http3TLSConfig(config *tls.Config) *tls.Config {
	config = config.Clone()
	config.NextProtos = []string{http3.NextProtoH3}
	return config
}

func normalizeDomain(domain string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
}

func proxyBackendHandler(handler http.Handler) http.Handler {
	return h2c.NewHandler(handler, &http2.Server{})
}

func validateProxyListenAddress(address string) error {
	return validateLoopbackListenAddress(address, "--listen for --behind-proxy")
}

func validateLoopbackListenAddress(address, option string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("parse %s: %w", option, err)
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return fmt.Errorf("%s requires a numeric port in 1..65535", option)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("%s requires a loopback address", option)
	}
	return nil
}
