use anyhow::Result;
use porta_server_rust::app::OperationsHandler;
use porta_server_rust::config::{version_requested, Config};
use porta_server_rust::data::router::Router;
use porta_server_rust::data::tun::NativeTun;
use porta_server_rust::http_handler::{AdminHttpHandler, PublicHttpHandler};
use porta_server_rust::integration::{
    AbuseLimiter, NativeAuthenticator, PoolAdapter, ProxyUsageAdapter, RegistryProxyAuthorizer,
    RouterAdapter, UsageAdapter, WebRegistryAdapter,
};
use porta_server_rust::ops::abuse::AbuseGuard;
use porta_server_rust::ops::acme::{AutomaticCertificateConfig, AutomaticCertificateManager};
use porta_server_rust::ops::admission::{ConnectionAdmission, RetryController};
use porta_server_rust::ops::metrics::Metrics;
use porta_server_rust::ops::shutdown::Drain;
use porta_server_rust::ops::system_readiness::{system_readiness, SystemReadinessConfig};
use porta_server_rust::ops::tls::StaticCertificateResolver;
use porta_server_rust::proxy::dial::PublicConnector;
use porta_server_rust::proxy::service::{ForwardProxy, DEFAULT_MAX_CONNECTIONS};
use porta_server_rust::server::{
    bind_tcp_listener, bind_udp_socket, serve_tcp, Handler, ServeOptions,
};
use porta_server_rust::state::pool::Pool;
use porta_server_rust::state::registry::ClientRegistry;
use porta_server_rust::state::usage::Store as UsageStore;
use porta_server_rust::transport::http2::{Http2Config, Http2Handler};
use porta_server_rust::transport::http3::{serve_quinn, Http3Config, Http3Server};
use porta_server_rust::transport::session::Services;
use porta_server_rust::web::admin::{AdminService, ClientRegistry as WebClientRegistry};
use porta_server_rust::web::landing::{load_landing_template_set, LandingSite};
use porta_server_rust::web::portal::Portal;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio_rustls::TlsAcceptor;
use tokio_util::task::TaskTracker;
use tracing_subscriber::EnvFilter;
use zeroize::Zeroizing;

#[tokio::main]
async fn main() {
    if version_requested(std::env::args_os().skip(1)) {
        println!("{}", porta_server_rust::VERSION.trim());
        return;
    }
    if let Err(error) = run().await {
        eprintln!("porta-server: {error:#}");
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
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
    let device = Arc::new(NativeTun::open(&config.interface, usize::from(config.mtu))?);
    let router = Arc::new(Router::new(device, Some(metrics.clone())));
    let bootstrap_token = Zeroizing::new(std::mem::take(&mut config.token));
    let registry =
        Arc::new(ClientRegistry::open(&config.client_registry, bootstrap_token.as_str()).await?);
    drop(bootstrap_token);
    let abuse = Arc::new(AbuseGuard::default_with_metrics(metrics.clone()));
    let leases = PoolAdapter::new(pool.clone());
    let services = Arc::new(Services {
        authenticator: NativeAuthenticator::new(registry.clone(), abuse.clone()),
        leases: leases.clone(),
        router: RouterAdapter::new(router.clone(), leases),
        usage: UsageAdapter::new(usage.clone()),
        metrics: metrics.clone(),
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
    })?;
    let metrics_token = Zeroizing::new(std::mem::take(&mut config.metrics_token));
    let operations: Arc<dyn Handler> = Arc::new(OperationsHandler::new(
        readiness,
        metrics.clone(),
        metrics_token.as_bytes().to_vec(),
        None,
    ));
    drop(metrics_token);
    let web_registry: Arc<dyn WebClientRegistry> =
        WebRegistryAdapter::new(registry.clone(), usage.clone());
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
        Arc::new(AdminService::new(
            web_registry,
            admin_token.as_bytes().to_vec(),
        )),
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
            },
            drain.cancellation(),
        )
        .await?;
        let acceptor = TlsAcceptor::from(manager.tcp_server_config());
        let quinn = manager.quinn_server_config();
        acme_manager = Some(manager);
        (Some(acceptor), Some(quinn))
    };

    let public_listener = bind_tcp_listener(public_address)?;
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
        let socket = bind_udp_socket(public_address)?;
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
        let listener = bind_tcp_listener(address)?;
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
    let mut run_error = tokio::select! {
        signal = shutdown_signal() => {
            signal.err()
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
    };
    drain.stop();
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
        None => Ok(()),
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

#[cfg(unix)]
async fn shutdown_signal() -> Result<()> {
    use tokio::signal::unix::{signal, SignalKind};

    let mut terminate = signal(SignalKind::terminate())?;
    tokio::select! {
        result = tokio::signal::ctrl_c() => result?,
        _ = terminate.recv() => {},
    }
    Ok(())
}

#[cfg(not(unix))]
async fn shutdown_signal() -> Result<()> {
    tokio::signal::ctrl_c().await?;
    Ok(())
}
