use anyhow::{Context as _, Result};
use porta_server_rust::app::OperationsHandler;
use porta_server_rust::config::{version_requested, Config};
use porta_server_rust::data::ratelimit::RateLimiters;
use porta_server_rust::data::router::Router;
use porta_server_rust::data::tun::NativeTun;
use porta_server_rust::dns::{Resolver, ResolverConfig};
use porta_server_rust::http_handler::{AdminHttpHandler, PublicHttpHandler};
use porta_server_rust::integration::{
    AbuseLimiter, AccountPolicyEnforcer, GatewayNetwork, NativeAuthenticator, PoolAdapter,
    ProxyUsageAdapter, RegistryProxyAuthorizer, RouterAdapter, SwitchConfig, UsageAdapter,
    WebRegistryAdapter,
};
use porta_server_rust::ops::abuse::AbuseGuard;
use porta_server_rust::ops::acme::{AutomaticCertificateConfig, AutomaticCertificateManager};
use porta_server_rust::ops::admission::{ConnectionAdmission, RetryController};
use porta_server_rust::ops::audit::AuditLog;
use porta_server_rust::ops::exits::ExitRules;
use porta_server_rust::ops::federation::FederationSync;
use porta_server_rust::ops::metrics::Metrics;
use porta_server_rust::ops::shutdown::Drain;
use porta_server_rust::ops::system_readiness::{
    system_readiness, SystemReadinessConfig, UpstreamReadiness,
};
use porta_server_rust::ops::tls::StaticCertificateResolver;
use porta_server_rust::proxy::dial::PublicConnector;
use porta_server_rust::proxy::service::{ForwardProxy, DEFAULT_MAX_CONNECTIONS};
use porta_server_rust::server::{listen_tcp, listen_udp, serve_tcp, Handler, ServeOptions};
use porta_server_rust::state::admins::AdminStore;
use porta_server_rust::state::pool::Pool;
use porta_server_rust::state::registry::ClientRegistry;
use porta_server_rust::state::usage::Store as UsageStore;
use porta_server_rust::transport::http2::{Http2Config, Http2Handler};
use porta_server_rust::transport::http3::{serve_quinn, Http3Config, Http3Server};
use porta_server_rust::transport::session::{Services, TunnelRouting};
use porta_server_rust::web::admin::FederationInfo;
use porta_server_rust::web::admin::{
    AdminService, ClientRegistry as WebClientRegistry, GatewayStatus, GatewayStatusProvider,
    UpstreamStatus,
};
use porta_server_rust::web::landing::{load_landing_template_set, LandingSite};
use porta_server_rust::web::oidc::{OidcClient, OidcConfig};
use porta_server_rust::web::portal::FederationSource;
use porta_server_rust::web::portal::Portal;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio_rustls::TlsAcceptor;
use tokio_util::task::TaskTracker;
use tracing_subscriber::EnvFilter;
use zeroize::Zeroizing;

fn main() {
    if version_requested(std::env::args_os().skip(1)) {
        println!("{}", porta_server_rust::VERSION.trim());
        return;
    }
    #[cfg(unix)]
    let program = porta_server_rust::ops::handoff::Program::current();
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("porta-server: start the async runtime: {error}");
            std::process::exit(1);
        }
    };
    let result = runtime.block_on(run());
    // No other thread may run while an in-place restart rearranges
    // descriptors: the runtime's own pipes are among them.
    runtime.shutdown_timeout(Duration::from_secs(5));
    match result {
        Ok(Stop::Exit) => {}
        #[cfg(unix)]
        Ok(Stop::Restart) => {
            let error = match program {
                Ok(program) => program.exec(),
                Err(error) => error,
            };
            eprintln!("porta-server: restart in place failed: {error}");
            std::process::exit(1);
        }
        #[cfg(not(unix))]
        Ok(Stop::Restart) => {}
        Err(error) => {
            eprintln!("porta-server: {error:#}");
            std::process::exit(1);
        }
    }
}

/// How the server stopped.
enum Stop {
    Exit,
    /// `SIGHUP`: re-execute in place, keeping sockets and interfaces.
    Restart,
}

async fn run() -> Result<Stop> {
    let mut config = Config::parse_and_validate()?;
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    if config.json_logs {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .json()
            .init();
    } else {
        tracing_subscriber::fmt().with_env_filter(filter).init();
    }
    tracing::info!(
        version = porta_server_rust::VERSION.trim(),
        listen = %config.listen,
        admin_listen = ?config.admin_listen,
        "Rust server core initialized"
    );
    #[cfg(unix)]
    porta_server_rust::ops::handoff::adopt_from_environment();
    let metrics = Arc::new(Metrics::default());
    let pool = Arc::new(match &config.lease_state {
        Some(path) => Pool::from_prefix_persistent(config.pool, path)?,
        None => Pool::from_prefix(config.pool)?,
    });
    let usage = Arc::new(UsageStore::open(
        config
            .usage_state
            .as_ref()
            .expect("validated configuration has a usage-state path"),
    )?);
    // The upstream TUN must exist before the client TUN appears: the network
    // helper starts once the client TUN exists and routes through both.
    let relays = upstream::open(&mut config, &metrics)?;
    let exit_rules = {
        let tables = config.exit_tables();
        (!tables.is_empty()).then(|| ExitRules::new(config.interface.clone(), tables))
    };
    let federation_status = config
        .federation_primary
        .as_deref()
        .map(FederationSync::status_for);
    let gateway_status = {
        let base = upstream::gateway_status(&relays);
        let federation = federation_status.clone();
        let serves_replicas =
            config.federation_primary.is_none() && !config.federation_token.is_empty();
        let routes = config
            .routes
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        let dns_domains = config.dns_domains.clone();
        let client_to_client = config.client_to_client;
        let peer_to_peer = config.peer_to_peer;
        let dns_resolver = config.dns_resolver;
        let exits = config.exit_names();
        let ipv6_pool = config.ipv6_pool.map(|prefix| prefix.to_string());
        let provider: GatewayStatusProvider = Arc::new(move || GatewayStatus {
            routes: routes.clone(),
            ipv6_pool: ipv6_pool.clone(),
            dns_domains: dns_domains.clone(),
            client_to_client,
            peer_to_peer,
            dns_resolver,
            exits: exits.clone(),
            federation: match &federation {
                Some(status) => Some(FederationInfo {
                    role: "replica",
                    status: status.lock().clone(),
                }),
                None => serves_replicas.then(|| FederationInfo {
                    role: "primary",
                    ..FederationInfo::default()
                }),
            },
            ..base()
        });
        provider
    };
    let ipv6 = config.ipv6();
    let device = Arc::new(NativeTun::open(&config.interface, usize::from(config.mtu))?);
    let router = Arc::new(Router::with_ipv6(device, Some(metrics.clone()), ipv6));
    let bootstrap_token = Zeroizing::new(std::mem::take(&mut config.token));
    let registry = Arc::new(match &config.federation_primary {
        Some(primary) => {
            tracing::info!(%primary, "mirroring accounts from the primary gateway");
            ClientRegistry::open_replica(&config.client_registry).await?
        }
        None => ClientRegistry::open(&config.client_registry, bootstrap_token.as_str()).await?,
    });
    drop(bootstrap_token);
    let federation_token = Zeroizing::new(std::mem::take(&mut config.federation_token));
    let federation_sync = match (&config.federation_primary, &federation_status) {
        (Some(primary), Some(status)) => Some(FederationSync::new(
            primary,
            federation_token.clone(),
            config.federation_ca.as_deref(),
            registry.clone(),
            status.clone(),
        )?),
        _ => None,
    };
    let abuse = Arc::new(AbuseGuard::default_with_metrics(metrics.clone()));
    let admins = Arc::new(
        AdminStore::open(
            config
                .admin_store
                .clone()
                .expect("validated configuration has an admin store"),
            "Porta",
        )
        .context("open the administrator store")?,
    );
    let audit = Arc::new(
        AuditLog::open(
            config
                .audit_log
                .clone()
                .expect("validated configuration has an audit log"),
        )
        .context("open the audit log")?,
    );
    let oidc = if config.oidc_issuer.is_empty() {
        None
    } else {
        Some(Arc::new(
            OidcClient::new(OidcConfig {
                issuer: config.oidc_issuer.clone(),
                client_id: config.oidc_client_id.clone(),
                client_secret: (!config.oidc_client_secret.is_empty())
                    .then(|| Zeroizing::new(std::mem::take(&mut config.oidc_client_secret))),
                redirect_url: config.oidc_redirect_url.clone(),
                ca: config.oidc_ca.clone(),
            })
            .map_err(anyhow::Error::msg)?,
        ))
    };
    let leases = PoolAdapter::with_ipv6(pool.clone(), ipv6);
    let rate_limits = RateLimiters::with_metrics(metrics.clone());
    let packet_router = RouterAdapter::with_switching(
        router.clone(),
        leases.clone(),
        rate_limits.clone(),
        SwitchConfig {
            client_to_client: config.client_to_client,
            peer_to_peer: config.peer_to_peer,
            always_reachable: [
                Some(IpAddr::V4(pool.gateway())),
                config.dns_address()?.map(IpAddr::V4),
                ipv6.map(|ipv6| IpAddr::V6(ipv6.gateway())),
            ]
            .into_iter()
            .flatten()
            .collect(),
            exits: exit_rules.clone(),
            names: Some(registry.clone()),
        },
    );
    let resolver = if config.dns_resolver {
        Some(Resolver::new(
            ResolverConfig {
                listen: pool.gateway(),
                upstreams: config.resolver_upstreams()?,
                forwards: config.resolver_forwards()?,
                blocklist: config.dns_blocklist.clone(),
            },
            packet_router.clone(),
        )?)
    } else {
        None
    };
    let tunnel_shutdown = tokio_util::sync::CancellationToken::new();
    let services = Arc::new(Services {
        shutdown: tunnel_shutdown.clone(),
        authenticator: NativeAuthenticator::with_usage(
            registry.clone(),
            abuse.clone(),
            usage.clone(),
        ),
        leases: leases.clone(),
        router: packet_router,
        usage: UsageAdapter::with_audit(usage.clone(), Some(audit.clone())),
        metrics: metrics.clone(),
        routing: TunnelRouting {
            // Split tunnels also route the client pool so that peers and
            // their subnets stay reachable.
            routes: if config.routes.is_empty() {
                Vec::new()
            } else {
                let mut routes = config.routes.clone();
                let pool = ipnet::IpNet::V4(config.pool.trunc());
                if !routes.contains(&pool) {
                    routes.push(pool);
                }
                routes
            },
            dns_domains: config.dns_domains.clone(),
            subnets: Vec::new(),
            ipv6: false,
        },
    });
    let dns = config.dns_address()?;
    let transport: Arc<dyn Handler> = Arc::new(Http2Handler::new(
        services.clone(),
        Http2Config {
            mtu: config.mtu,
            dns,
            ..Http2Config::default()
        },
    )?);
    let public_address = config.listen_address()?;
    let readiness = system_readiness(SystemReadinessConfig {
        interface: config.interface.clone(),
        gateway: pool.gateway(),
        pool: pool.network(),
        mtu: u32::from(config.mtu),
        egress_interface: (!config.egress_interface.is_empty())
            .then(|| config.egress_interface.clone()),
        require_nat: config.readiness_require_nat,
        require_input_guard: !config.behind_proxy,
        public_port: if config.behind_proxy {
            0
        } else {
            public_address.port()
        },
        timeout: config.readiness_timeout,
        egress_url: (!config.readiness_egress_url.is_empty())
            .then(|| config.readiness_egress_url.clone()),
        dns_name: (!config.readiness_dns_name.is_empty())
            .then(|| config.readiness_dns_name.clone()),
        dns_address: config.dns_address()?.map(IpAddr::V4),
        upstream: relays
            .iter()
            .find(|relay| relay.name().is_none())
            .map(|relay| relay.readiness()),
        exits: relays
            .iter()
            .filter_map(|relay| Some((relay.name()?.to_owned(), relay.readiness())))
            .collect(),
        ipv6: ipv6.map(|ipv6| (ipv6.gateway(), ipv6.prefix())),
    })?;
    let metrics_token = Zeroizing::new(std::mem::take(&mut config.metrics_token));
    let operations: Arc<dyn Handler> = Arc::new(OperationsHandler::new(
        readiness,
        metrics.clone(),
        metrics_token.as_bytes().to_vec(),
        None,
    ));
    drop(metrics_token);
    let web_registry: Arc<dyn WebClientRegistry> = WebRegistryAdapter::with_network(
        registry.clone(),
        usage.clone(),
        GatewayNetwork {
            exits: config.exit_names(),
            reserved: vec![config.pool.trunc()],
        },
    );
    let downloads = config
        .client_downloads
        .as_ref()
        .map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_default();
    let trust_proxy_headers = config.behind_proxy || config.trust_proxy_headers;
    let admin_token = Zeroizing::new(std::mem::take(&mut config.admin_token));
    let mut portal = Portal::new(
        web_registry.clone(),
        admin_token.to_string(),
        downloads,
        trust_proxy_headers,
    )
    .map_err(anyhow::Error::msg)?;
    portal.set_abuse_guard(Some(abuse.clone()));
    portal.set_gateway_status(gateway_status.clone());
    portal.set_identity(Some(admins.clone()), Some(audit.clone()), oidc);
    if config.federation_primary.is_none() && !federation_token.is_empty() {
        let source = registry.clone();
        portal.set_federation(Some(FederationSource {
            token: federation_token.clone(),
            export: Arc::new(move || serde_json::to_vec(&source.export()).unwrap_or_default()),
        }));
    }
    let portal = Arc::new(portal);
    let landing = Arc::new(match &config.landing_template_dir {
        Some(directory) => LandingSite::with_templates(
            config.landing_page,
            load_landing_template_set(directory).map_err(anyhow::Error::msg)?,
        ),
        None => LandingSite::new(config.landing_page),
    });
    let proxy = if config.disable_forward_proxy {
        None
    } else {
        let mut proxy = ForwardProxy::with_components(
            RegistryProxyAuthorizer::new(registry.clone()),
            Arc::new(PublicConnector::default()),
            ProxyUsageAdapter::new(usage.clone()),
            DEFAULT_MAX_CONNECTIONS,
        );
        proxy.set_camouflage(config.landing_page);
        proxy.set_authentication_limiter(Some(AbuseLimiter::new(abuse)));
        Some(Arc::new(proxy))
    };
    let drain = Drain::new();
    let http3 = Arc::new(Http3Server::new(
        services,
        portal.clone(),
        landing.clone(),
        Http3Config {
            mtu: config.mtu,
            dns,
            auto_mtu: config.auto_mtu,
            ..Http3Config::default()
        },
    )?);
    let public_handler: Arc<dyn Handler> = Arc::new(PublicHttpHandler::new(
        proxy,
        portal,
        landing,
        transport,
        trust_proxy_headers,
        drain.cancellation(),
    ));
    let admin_handler: Arc<dyn Handler> = Arc::new(AdminHttpHandler::new(
        Arc::new(
            AdminService::new(web_registry, admin_token.as_bytes().to_vec())
                .with_gateway_status(gateway_status)
                .with_identity(Some(admins), Some(audit)),
        ),
        operations,
    ));
    drop(admin_token);
    let connections = TaskTracker::new();
    let router_shutdown = tokio_util::sync::CancellationToken::new();
    let router_cancellation = router_shutdown.clone();
    let mut router_task = tokio::spawn({
        let router = router.clone();
        async move {
            router
                .run(&router_cancellation)
                .await
                .map_err(anyhow::Error::from)
        }
    });
    let usage_shutdown = tokio_util::sync::CancellationToken::new();
    let usage_cancellation = usage_shutdown.clone();
    let mut usage_task = tokio::spawn({
        let usage = usage.clone();
        async move {
            usage
                .run(usage_cancellation, Duration::from_secs(30))
                .await
                .map_err(anyhow::Error::from)
        }
    });
    let policy_shutdown = tokio_util::sync::CancellationToken::new();
    let policy_task = tokio::spawn({
        let enforcer = AccountPolicyEnforcer::new(registry.clone(), usage.clone(), rate_limits);
        let cancellation = policy_shutdown.clone();
        async move { enforcer.run(cancellation).await }
    });
    let upstream_shutdown = tokio_util::sync::CancellationToken::new();
    let mut upstream_task = (!relays.is_empty()).then(|| {
        let cancellation = upstream_shutdown.clone();
        tokio::spawn(async move {
            futures_util::future::try_join_all(
                relays
                    .into_iter()
                    .map(|relay| relay.run(cancellation.clone())),
            )
            .await
            .map(|_| ())
        })
    });
    let exit_shutdown = tokio_util::sync::CancellationToken::new();
    let exit_task = exit_rules.map(|rules| tokio::spawn(rules.run(exit_shutdown.clone())));
    let federation_shutdown = tokio_util::sync::CancellationToken::new();
    let federation_task =
        federation_sync.map(|sync| tokio::spawn(sync.run(federation_shutdown.clone())));
    let resolver_shutdown = tokio_util::sync::CancellationToken::new();
    let mut resolver_task = match resolver {
        Some(resolver) => {
            let listeners = resolver.bind()?;
            Some(tokio::spawn(
                resolver.run(listeners, resolver_shutdown.clone()),
            ))
        }
        None => None,
    };
    let admission = Arc::new(ConnectionAdmission::new(metrics.clone()));
    let retry = Arc::new(RetryController::new(admission.as_ref(), metrics));
    let mut acme_manager = None;
    let mut tls_reload_task = None;
    let (tls, quinn_tls) = if config.behind_proxy {
        (None, None)
    } else if let (Some(certificate), Some(private_key)) = (&config.tls_cert, &config.tls_key) {
        let resolver = StaticCertificateResolver::open(certificate, private_key)?;
        tls_reload_task = Some(resolver.spawn_reload(Duration::from_secs(1), drain.cancellation()));
        let quinn = resolver.quinn_server_config()?;
        (
            Some(TlsAcceptor::from(Arc::new(
                resolver.server_config(vec![b"h2".to_vec(), b"http/1.1".to_vec()]),
            ))),
            Some(quinn),
        )
    } else {
        let manager = AutomaticCertificateManager::start(
            AutomaticCertificateConfig {
                domain: config
                    .acme_domain
                    .clone()
                    .expect("validated ACME mode has a domain"),
                email: config.acme_email.clone(),
                cache_directory: config.acme_cache.clone(),
                http_listen: config.acme_http_listen.clone(),
                https_port: public_address.port(),
            },
            drain.cancellation(),
        )
        .await?;
        let acceptor = TlsAcceptor::from(manager.tcp_server_config());
        let quinn = manager.quinn_server_config();
        acme_manager = Some(manager);
        (Some(acceptor), Some(quinn))
    };

    let public_listener = listen_tcp(public_address)?;
    let mut public = tokio::spawn(serve_tcp(
        public_listener,
        tls,
        public_handler,
        ServeOptions {
            admission: Some(admission.clone()),
            drain: drain.clone(),
            connections: connections.clone(),
            initial_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(90),
        },
    ));
    let mut http3_task = if let Some(server_config) = quinn_tls {
        let socket = listen_udp(public_address)?;
        let endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            Some(server_config),
            socket,
            Arc::new(quinn::TokioRuntime),
        )?;
        Some(tokio::spawn(serve_quinn(
            endpoint,
            http3,
            admission,
            retry,
            drain.cancellation(),
        )))
    } else {
        None
    };
    let mut admin = if let Some(address) = config.admin_address()? {
        let listener = listen_tcp(address)?;
        Some(tokio::spawn(serve_tcp(
            listener,
            None,
            admin_handler,
            ServeOptions {
                admission: None,
                drain: drain.clone(),
                connections: connections.clone(),
                initial_timeout: Duration::from_secs(5),
                idle_timeout: Duration::from_secs(30),
            },
        )))
    } else {
        None
    };

    let mut public_completed = false;
    let mut admin_completed = false;
    let mut http3_completed = false;
    let mut router_completed = false;
    let mut usage_completed = false;
    let mut upstream_completed = false;
    #[cfg(unix)]
    porta_server_rust::ops::handoff::release_unclaimed();
    let mut stop = Stop::Exit;
    let mut run_error = tokio::select! {
        signal = shutdown_signal() => match signal {
            Ok(next) => {
                stop = next;
                if matches!(stop, Stop::Restart) {
                    porta_server_rust::ops::shutdown::mark_restarting();
                    tracing::info!("restarting in place; clients reconnect to the new process");
                }
                None
            }
            Err(error) => Some(error),
        },
        result = &mut public => {
            public_completed = true;
            task_error(result)
        },
        result = async {
            match admin.as_mut() {
                Some(task) => task.await,
                None => std::future::pending::<Result<Result<()>, tokio::task::JoinError>>().await,
            }
        } => {
            admin_completed = true;
            task_error(result)
        },
        result = async {
            match http3_task.as_mut() {
                Some(task) => task.await,
                None => std::future::pending::<Result<Result<()>, tokio::task::JoinError>>().await,
            }
        } => {
            http3_completed = true;
            task_error(result)
        },
        result = &mut router_task => {
            router_completed = true;
            task_error(result)
        },
        result = &mut usage_task => {
            usage_completed = true;
            task_error(result)
        },
        result = async {
            match upstream_task.as_mut() {
                Some(task) => task.await,
                None => std::future::pending::<Result<Result<()>, tokio::task::JoinError>>().await,
            }
        } => {
            upstream_completed = true;
            task_error(result)
        },
    };
    drain.stop();
    tunnel_shutdown.cancel();
    connections.close();
    if !drain.wait(Duration::from_secs(10)).await {
        tracing::warn!(
            active = drain.active(),
            "handlers still active during shutdown"
        );
    }
    if tokio::time::timeout(Duration::from_secs(10), connections.wait())
        .await
        .is_err()
    {
        tracing::warn!("public connections still active during shutdown");
    }
    if !public_completed {
        let error = task_error(public.await);
        if run_error.is_none() {
            run_error = error;
        }
    }
    if let Some(admin) = admin {
        if !admin_completed {
            let error = task_error(admin.await);
            if run_error.is_none() {
                run_error = error;
            }
        }
    }
    if let Some(http3) = http3_task {
        if !http3_completed {
            let error = task_error(http3.await);
            if run_error.is_none() {
                run_error = error;
            }
        }
    }
    if let Err(error) = registry.close().await {
        if run_error.is_none() {
            run_error = Some(error.into());
        }
    }
    policy_shutdown.cancel();
    if let Err(error) = policy_task.await {
        if run_error.is_none() {
            run_error = Some(error.into());
        }
    }
    federation_shutdown.cancel();
    if let Some(task) = federation_task {
        let error = task_error(task.await);
        if run_error.is_none() {
            run_error = error;
        }
    }
    resolver_shutdown.cancel();
    if let Some(task) = resolver_task.take() {
        let error = task_error(task.await);
        if run_error.is_none() {
            run_error = error;
        }
    }
    exit_shutdown.cancel();
    if let Some(task) = exit_task {
        let error = task_error(task.await);
        if run_error.is_none() {
            run_error = error;
        }
    }
    upstream_shutdown.cancel();
    if let Some(task) = upstream_task {
        if !upstream_completed {
            let error = task_error(task.await);
            if run_error.is_none() {
                run_error = error;
            }
        }
    }
    router_shutdown.cancel();
    if !router_completed {
        let error = task_error(router_task.await);
        if run_error.is_none() {
            run_error = error;
        }
    }
    usage_shutdown.cancel();
    if !usage_completed {
        let error = task_error(usage_task.await);
        if run_error.is_none() {
            run_error = error;
        }
    }
    if let Some(task) = tls_reload_task {
        let error = task.await.err().map(anyhow::Error::from);
        if run_error.is_none() {
            run_error = error;
        }
    }
    if let Some(manager) = acme_manager {
        let error = manager.shutdown().await.err();
        if run_error.is_none() {
            run_error = error;
        }
    }
    match run_error {
        Some(error) => Err(error),
        None => Ok(stop),
    }
}

fn task_error(
    result: std::result::Result<Result<()>, tokio::task::JoinError>,
) -> Option<anyhow::Error> {
    match result {
        Ok(Ok(())) => None,
        Ok(Err(error)) => Some(error),
        Err(error) => Some(error.into()),
    }
}

#[cfg(target_os = "linux")]
mod upstream {
    use super::*;
    use porta_client::tunnel::Transport;
    use porta_server_rust::config::UpstreamTransport;
    use porta_server_rust::upstream::{Upstream, UpstreamConfig};
    use tokio_util::sync::CancellationToken;

    /// A next-hop tunnel: the default upstream (no name) or a named exit.
    pub struct Relay {
        name: Option<String>,
        upstream: Arc<Upstream>,
    }

    /// Opens the default upstream, if any, followed by every named exit.
    pub fn open(config: &mut Config, metrics: &Arc<Metrics>) -> Result<Vec<Relay>> {
        let transport = match config.upstream_transport {
            UpstreamTransport::Auto => Transport::Auto,
            UpstreamTransport::H3 => Transport::Http3,
            UpstreamTransport::H2 => Transport::Http2,
        };
        let identity_path = config.upstream_identity.clone();
        let base = |url: String, token: String, interface: String, local_address| UpstreamConfig {
            url,
            token: Zeroizing::new(token),
            transport,
            interface,
            local_address,
            identity_path: identity_path
                .clone()
                .expect("validated upstream configuration has an identity path"),
            ca_path: config.upstream_ca.clone(),
            thumbprint: (!config.upstream_thumbprint.is_empty())
                .then(|| config.upstream_thumbprint.clone()),
        };
        let mut relays = Vec::new();
        if let Some(url) = config.upstream.clone() {
            let upstream = Upstream::open(
                base(
                    url,
                    std::mem::take(&mut config.upstream_token),
                    config.upstream_interface.clone(),
                    config.upstream_address,
                ),
                metrics.clone(),
            )?;
            relays.push(Relay {
                name: None,
                upstream: Arc::new(upstream),
            });
        }
        for exit in &mut config.exits {
            let upstream = Upstream::open(
                base(
                    exit.url.clone(),
                    std::mem::take(&mut exit.token),
                    exit.interface.clone(),
                    exit.address,
                ),
                metrics.clone(),
            )
            .with_context(|| format!("open exit {}", exit.name))?;
            relays.push(Relay {
                name: Some(exit.name.clone()),
                upstream: Arc::new(upstream),
            });
        }
        if let (Some(path), false) = (&config.upstream_ca, relays.is_empty()) {
            tracing::info!(ca = %path.display(), "next-hop gateways use a private CA");
        }
        Ok(relays)
    }

    pub fn gateway_status(relays: &[Relay]) -> GatewayStatusProvider {
        let relays = relays
            .iter()
            .map(|relay| {
                (
                    relay.name.clone().unwrap_or_default(),
                    relay.upstream.status(),
                    relay.upstream.url().to_owned(),
                    relay.upstream.interface().to_owned(),
                )
            })
            .collect::<Vec<_>>();
        Arc::new(move || {
            let upstreams = relays
                .iter()
                .map(|(name, status, url, interface)| {
                    let snapshot = status.snapshot();
                    UpstreamStatus {
                        name: name.clone(),
                        url: url.clone(),
                        interface: interface.clone(),
                        connected: snapshot.connected,
                        address: snapshot.address,
                        transport: snapshot.transport.map(str::to_owned),
                        error: snapshot.error,
                    }
                })
                .collect::<Vec<_>>();
            GatewayStatus {
                version: porta_server_rust::VERSION.trim().to_owned(),
                upstream: upstreams
                    .iter()
                    .find(|upstream| upstream.name.is_empty())
                    .cloned(),
                upstreams,
                ..GatewayStatus::default()
            }
        })
    }

    impl Relay {
        pub fn name(&self) -> Option<&str> {
            self.name.as_deref()
        }

        pub fn readiness(&self) -> UpstreamReadiness {
            let status = self.upstream.status();
            UpstreamReadiness {
                interface: self.upstream.interface().to_owned(),
                status: Arc::new(move || status.check()),
            }
        }

        pub async fn run(self, cancellation: CancellationToken) -> Result<()> {
            self.upstream.run(cancellation).await
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod upstream {
    use super::*;

    pub struct Relay;

    pub fn gateway_status(_relays: &[Relay]) -> GatewayStatusProvider {
        Arc::new(|| GatewayStatus {
            version: porta_server_rust::VERSION.trim().to_owned(),
            ..GatewayStatus::default()
        })
    }

    pub fn open(config: &mut Config, _metrics: &Arc<Metrics>) -> Result<Vec<Relay>> {
        if config.upstream.is_some() || !config.exits.is_empty() {
            anyhow::bail!("--upstream and --exit relaying require Linux");
        }
        Ok(Vec::new())
    }

    impl Relay {
        pub fn name(&self) -> Option<&str> {
            None
        }

        pub fn readiness(&self) -> UpstreamReadiness {
            unreachable!("non-Linux builds never create an upstream relay")
        }

        pub async fn run(self, _cancellation: tokio_util::sync::CancellationToken) -> Result<()> {
            Ok(())
        }
    }
}

#[cfg(unix)]
async fn shutdown_signal() -> Result<Stop> {
    use tokio::signal::unix::{signal, SignalKind};

    let mut terminate = signal(SignalKind::terminate())?;
    let mut hangup = signal(SignalKind::hangup())?;
    Ok(tokio::select! {
        result = tokio::signal::ctrl_c() => {
            result?;
            Stop::Exit
        }
        _ = terminate.recv() => Stop::Exit,
        _ = hangup.recv() => Stop::Restart,
    })
}

#[cfg(not(unix))]
async fn shutdown_signal() -> Result<Stop> {
    tokio::signal::ctrl_c().await?;
    Ok(Stop::Exit)
}
