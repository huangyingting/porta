#[cfg(all(target_os = "linux", not(target_os = "android")))]
mod linux {
    use std::path::PathBuf;
    use std::time::Duration;

    use clap::{ArgAction, Parser, ValueEnum};
    use porta_client::linux::client::{self, Event, State};
    use porta_client::tunnel::Transport;
    use tokio_util::sync::CancellationToken;

    #[derive(Clone, Copy, Debug, Default, ValueEnum)]
    enum TransportArgument {
        #[default]
        Auto,
        H3,
        H2,
    }

    impl From<TransportArgument> for Transport {
        fn from(value: TransportArgument) -> Self {
            match value {
                TransportArgument::Auto => Self::Auto,
                TransportArgument::H3 => Self::Http3,
                TransportArgument::H2 => Self::Http2,
            }
        }
    }

    #[derive(Debug, Parser)]
    #[command(
        name = "porta-client",
        about = "Porta VPN tunnel client",
        disable_version_flag = true
    )]
    struct Arguments {
        #[arg(
            long,
            default_value = "",
            help = "Gateway origin, for example https://vpn.example.com:8443"
        )]
        server: String,
        #[arg(
            long,
            value_enum,
            default_value_t,
            help = "Tunnel transport: auto (HTTP/3 with safe HTTP/2 fallback), h3, or h2"
        )]
        transport: TransportArgument,
        #[arg(long, default_value = "porta0", help = "TUN interface name")]
        interface: String,
        #[arg(long, help = "Optional absolute private device identity path")]
        identity: Option<PathBuf>,
        #[arg(long, help = "Optional PEM CA certificate")]
        ca: Option<PathBuf>,
        #[arg(long, help = "Optional SHA-256 gateway certificate thumbprint")]
        thumbprint: Option<String>,
        #[arg(
            long,
            action = ArgAction::SetTrue,
            help = "Skip TLS certificate verification (development only)"
        )]
        insecure: bool,
        #[arg(
            long,
            default_value_t = true,
            num_args = 0..=1,
            default_missing_value = "true",
            require_equals = true,
            action = ArgAction::Set,
            help = "Retry transient startup failures and interrupted tunnels"
        )]
        reconnect: bool,
        #[arg(
            long,
            default_value = "30s",
            value_parser = parse_duration,
            help = "Maximum reconnect delay"
        )]
        reconnect_max_delay: Duration,
        #[arg(
            long,
            default_value_t = false,
            num_args = 0..=1,
            default_missing_value = "true",
            require_equals = true,
            action = ArgAction::Set,
            help = "Manage routes, DNS, and leak protection yourself"
        )]
        manual_network: bool,
        #[arg(
            long,
            action = ArgAction::SetTrue,
            help = "Restore Porta networking and exit"
        )]
        cleanup_network: bool,
        #[arg(
            long,
            default_value = "/var/lib/porta/network-state.json",
            help = "Network recovery state file"
        )]
        network_state: PathBuf,
    }

    fn parse_duration(value: &str) -> Result<Duration, String> {
        humantime::parse_duration(value).map_err(|error| error.to_string())
    }

    pub async fn run() -> Result<(), client::RunError> {
        let arguments = Arguments::parse();
        let cancellation = CancellationToken::new();
        let signal_cancellation = cancellation.clone();
        let signal_task = tokio::spawn(async move {
            let mut terminate =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .expect("install SIGTERM handler");
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = terminate.recv() => {}
            }
            signal_cancellation.cancel();
        });

        let result = if arguments.cleanup_network {
            client::cleanup_network(arguments.network_state, &cancellation).await
        } else {
            let token = std::env::var("PORTA_TOKEN").unwrap_or_default();
            client::run(
                client::Config {
                    server_url: arguments.server,
                    token,
                    transport: arguments.transport.into(),
                    interface_name: arguments.interface,
                    identity_path: arguments.identity,
                    ca_path: arguments.ca,
                    thumbprint: arguments.thumbprint,
                    insecure: arguments.insecure,
                    reconnect: arguments.reconnect,
                    reconnect_max_delay: arguments.reconnect_max_delay,
                    manual_network: arguments.manual_network,
                    network_state: arguments.network_state,
                },
                &cancellation,
                print_event,
            )
            .await
        };
        signal_task.abort();
        let _ = signal_task.await;
        result
    }

    fn print_event(event: Event) {
        if event.state == State::Connected {
            let lease = event.lease.expect("connected event includes a lease");
            eprintln!(
                "porta-client: connected address={} dns={} mtu={} transport={} uploaded={} downloaded={}",
                lease.address,
                lease
                    .dns
                    .map_or_else(|| "-".to_owned(), |address| address.to_string()),
                lease.mtu,
                transport_name(event.transport),
                event.bytes_uploaded,
                event.bytes_downloaded
            );
        } else {
            eprintln!("porta-client: {}", event.message);
        }
    }

    fn transport_name(transport: Transport) -> &'static str {
        match transport {
            Transport::Auto => "auto",
            Transport::Http2 => "h2",
            Transport::Http3 => "h3",
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn automatic_networking_is_the_linux_default() {
            let arguments = Arguments::try_parse_from(["porta-client"]).unwrap();
            assert!(!arguments.manual_network);
        }

        #[test]
        fn linux_token_is_not_accepted_on_the_command_line() {
            let error =
                Arguments::try_parse_from(["porta-client", "--token", "secret"]).unwrap_err();
            assert_eq!(error.kind(), clap::error::ErrorKind::UnknownArgument);
        }

        #[test]
        fn linux_identity_path_is_explicit() {
            let arguments =
                Arguments::try_parse_from(["porta-client", "--identity", "/run/porta/id.json"])
                    .unwrap();
            assert_eq!(
                arguments.identity,
                Some(PathBuf::from("/run/porta/id.json"))
            );
        }
    }
}

#[cfg(target_os = "windows")]
mod windows {
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::Duration;

    use clap::{ArgAction, Parser, ValueEnum};
    use porta_client::tls;
    use porta_client::tunnel::Transport;
    use porta_client::windows::client::{self, Event};
    use porta_client::windows::{network::NetworkManager, paths};
    use tokio_util::sync::CancellationToken;
    use url::Url;

    #[derive(Clone, Copy, Debug, Default, ValueEnum)]
    enum TransportArgument {
        #[default]
        Auto,
        H3,
        H2,
    }

    impl From<TransportArgument> for Transport {
        fn from(value: TransportArgument) -> Self {
            match value {
                TransportArgument::Auto => Self::Auto,
                TransportArgument::H3 => Self::Http3,
                TransportArgument::H2 => Self::Http2,
            }
        }
    }

    #[derive(Debug, Parser)]
    #[command(
        name = "porta-client",
        about = "Porta VPN tunnel client",
        disable_version_flag = true
    )]
    struct Arguments {
        #[arg(
            long,
            default_value = "",
            help = "Gateway origin, for example https://vpn.example.com:8443"
        )]
        server: String,
        #[arg(
            long,
            value_enum,
            default_value_t,
            help = "Tunnel transport: auto (HTTP/3 with safe HTTP/2 fallback), h3, or h2"
        )]
        transport: TransportArgument,
        #[arg(long, default_value = "Porta", help = "Wintun interface name")]
        interface: String,
        #[arg(long, help = "Optional PEM CA certificate")]
        ca: Option<PathBuf>,
        #[arg(long, help = "Optional SHA-256 gateway certificate thumbprint")]
        thumbprint: Option<String>,
        #[arg(
            long,
            action = ArgAction::SetTrue,
            help = "Skip TLS certificate verification (development only)"
        )]
        insecure: bool,
        #[arg(
            long,
            default_value_t = true,
            num_args = 0..=1,
            default_missing_value = "true",
            require_equals = true,
            action = ArgAction::Set,
            help = "Retry transient startup failures and interrupted tunnels"
        )]
        reconnect: bool,
        #[arg(
            long,
            default_value = "30s",
            value_parser = parse_duration,
            help = "Maximum reconnect delay"
        )]
        reconnect_max_delay: Duration,
        #[arg(
            long,
            default_value_t = false,
            num_args = 0..=1,
            default_missing_value = "true",
            require_equals = true,
            action = ArgAction::Set,
            help = "Manage routes, DNS, and leak protection yourself"
        )]
        manual_network: bool,
        #[arg(
            long,
            action = ArgAction::SetTrue,
            help = "Restore Porta networking and exit"
        )]
        cleanup_network: bool,
        #[arg(long, help = "Absolute path to the official wintun.dll")]
        wintun: Option<PathBuf>,
    }

    fn parse_duration(value: &str) -> Result<Duration, String> {
        humantime::parse_duration(value).map_err(|error| error.to_string())
    }

    pub async fn run() -> Result<(), client::RunError> {
        let arguments = Arguments::parse();
        let network_state = paths::network_state_path()
            .map_err(|error| client::RunError::Invalid(error.to_string()))?;
        if arguments.cleanup_network {
            let mut manager = NetworkManager::open(network_state)?;
            return manager.down().await.map_err(client::RunError::Network);
        }

        let server = parse_origin(&arguments.server)?;
        let token = std::env::var("PORTA_TOKEN").unwrap_or_default();
        if token.is_empty() {
            return Err(client::RunError::Invalid(
                "gateway token is required".to_owned(),
            ));
        }
        let tls = tls::config(
            arguments.ca.as_deref(),
            arguments.thumbprint.as_deref(),
            arguments.insecure,
        )
        .map_err(|error| client::RunError::Invalid(error.to_string()))?;
        let wintun_path = arguments.wintun.map(absolute).transpose()?;
        let cancellation = CancellationToken::new();
        let signal_cancellation = cancellation.clone();
        let signal_task = tokio::spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            signal_cancellation.cancel();
        });
        let result = client::run(
            client::Config {
                server,
                token,
                tls,
                transport: arguments.transport.into(),
                interface_name: arguments.interface,
                network_state_path: network_state,
                wintun_path,
                manual_network: arguments.manual_network,
                reconnect: arguments.reconnect,
                connect_timeout: Duration::from_secs(15),
                reconnect_max_delay: arguments.reconnect_max_delay,
            },
            cancellation,
            Arc::new(print_event),
        )
        .await;
        signal_task.abort();
        let _ = signal_task.await;
        result
    }

    fn parse_origin(value: &str) -> Result<Url, client::RunError> {
        let url = Url::parse(value)
            .map_err(|error| client::RunError::Invalid(format!("invalid server URL: {error}")))?;
        if url.scheme() != "https"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || !matches!(url.path(), "" | "/")
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(client::RunError::Invalid(
                "server URL must be an HTTPS origin".to_owned(),
            ));
        }
        Ok(url)
    }

    fn absolute(path: PathBuf) -> Result<PathBuf, client::RunError> {
        if path.is_absolute() {
            return Ok(path);
        }
        std::env::current_dir()
            .map(|directory| directory.join(path))
            .map_err(|error| client::RunError::Invalid(error.to_string()))
    }

    fn print_event(event: Event) {
        match event {
            Event::RecoveringNetwork => {
                eprintln!("porta-client: recovering fail-closed network state")
            }
            Event::Connecting {
                attempt,
                remote_address,
            } => eprintln!("porta-client: connecting attempt={attempt} endpoint={remote_address}"),
            Event::ConfiguringNetwork => eprintln!("porta-client: configuring network"),
            Event::Connected(info) => eprintln!(
                "porta-client: connected address={} dns={} mtu={} transport={:?}",
                info.lease.address,
                info.lease
                    .dns
                    .map_or_else(|| "-".to_owned(), |address| address.to_string()),
                info.lease.mtu,
                info.transport
            ),
            Event::Progress {
                uploaded_bytes,
                downloaded_bytes,
            } => eprintln!("porta-client: uploaded={uploaded_bytes} downloaded={downloaded_bytes}"),
            Event::Reconnecting { reason, delay } => eprintln!(
                "porta-client: reconnecting in {}: {reason}",
                humantime::format_duration(delay)
            ),
            Event::Stopping => eprintln!("porta-client: stopping"),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn automatic_networking_is_the_windows_cli_default() {
            let arguments = Arguments::try_parse_from(["porta-client"]).unwrap();
            assert!(!arguments.manual_network);
        }

        #[test]
        fn windows_token_is_not_accepted_on_the_command_line() {
            let error =
                Arguments::try_parse_from(["porta-client", "--token", "secret"]).unwrap_err();
            assert_eq!(error.kind(), clap::error::ErrorKind::UnknownArgument);
        }
    }
}

#[cfg(all(target_os = "linux", not(target_os = "android")))]
#[tokio::main]
async fn main() {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    if arguments.len() == 1 && matches!(arguments[0].as_str(), "--version" | "-version") {
        println!("{}", porta_client::VERSION.trim());
        return;
    }
    if let Err(error) = linux::run().await {
        if !matches!(error, porta_client::linux::client::RunError::Cancelled) {
            eprintln!("porta-client: {error}");
            std::process::exit(1);
        }
    }
}

#[cfg(target_os = "windows")]
#[tokio::main]
async fn main() {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    if arguments.len() == 1 && matches!(arguments[0].as_str(), "--version" | "-version") {
        println!("{}", porta_client::VERSION.trim());
        return;
    }
    if let Err(error) = windows::run().await {
        if !matches!(error, porta_client::windows::client::RunError::Cancelled) {
            eprintln!("porta-client: {error}");
            std::process::exit(1);
        }
    }
}

#[cfg(not(any(
    all(target_os = "linux", not(target_os = "android")),
    target_os = "windows"
)))]
fn main() {
    println!("{}", porta_client::VERSION.trim());
}
