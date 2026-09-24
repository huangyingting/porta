use std::collections::HashMap;
use std::env;
use std::ffi::OsString;
use std::net::Ipv4Addr;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use p256::ecdsa::SigningKey;
use p256::elliptic_curve::rand_core::OsRng;
use porta_client::tunnel::{self, ClientError, Connection, Transport};
use serde::Serialize;
use tokio::sync::Barrier;
use tokio::task::JoinSet;
use tokio::time::{timeout, Instant};
use tokio_util::sync::CancellationToken;

const BENCHMARK_TOKEN: &str = "benchmark-token-1234567890";
const RECEIVE_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Clone, Debug, Eq, PartialEq)]
struct Arguments {
    url: String,
    clients: usize,
    duration: Duration,
    warmup: Duration,
    payload: usize,
    transport: String,
    require_auto_mtu: bool,
    inflight: usize,
}

impl Default for Arguments {
    fn default() -> Self {
        Self {
            url: "https://127.0.0.1:18443".to_owned(),
            clients: 1,
            duration: Duration::from_secs(6),
            warmup: Duration::from_secs(2),
            payload: 1200,
            transport: "h2".to_owned(),
            require_auto_mtu: false,
            inflight: 1,
        }
    }
}

enum ParseOutcome {
    Run(Arguments),
    Help,
}

impl Arguments {
    fn parse() -> Result<ParseOutcome> {
        Self::parse_from(env::args_os())
    }

    fn parse_from(values: impl IntoIterator<Item = OsString>) -> Result<ParseOutcome> {
        let mut arguments = Self::default();
        let mut values = values.into_iter();
        let _program = values.next();
        while let Some(raw) = values.next() {
            let raw = raw
                .into_string()
                .map_err(|_| anyhow!("arguments must be valid UTF-8"))?;
            if matches!(raw.as_str(), "-h" | "--help") {
                return Ok(ParseOutcome::Help);
            }
            let option = raw
                .strip_prefix("--")
                .or_else(|| raw.strip_prefix('-'))
                .ok_or_else(|| anyhow!("unexpected positional argument {raw:?}"))?;
            let (name, inline_value) = option
                .split_once('=')
                .map_or((option, None), |(name, value)| (name, Some(value)));
            let mut value = || -> Result<String> {
                if let Some(value) = inline_value {
                    return Ok(value.to_owned());
                }
                values
                    .next()
                    .ok_or_else(|| anyhow!("flag needs an argument: -{name}"))?
                    .into_string()
                    .map_err(|_| anyhow!("arguments must be valid UTF-8"))
            };
            match name {
                "url" => arguments.url = value()?,
                "clients" => arguments.clients = parse_number(name, &value()?)?,
                "duration" => arguments.duration = parse_duration(name, &value()?)?,
                "warmup" => arguments.warmup = parse_duration(name, &value()?)?,
                "payload" => arguments.payload = parse_number(name, &value()?)?,
                "transport" => arguments.transport = value()?,
                "inflight" => arguments.inflight = parse_number(name, &value()?)?,
                "require-auto-mtu" => {
                    arguments.require_auto_mtu = inline_value.map_or(Ok(true), parse_bool)?
                }
                _ => bail!("flag provided but not defined: -{name}"),
            }
        }
        arguments.validate()?;
        Ok(ParseOutcome::Run(arguments))
    }

    fn validate(&self) -> Result<()> {
        if self.clients == 0
            || self.duration.is_zero()
            || !(36..=1400).contains(&self.payload)
            || !(1..=256).contains(&self.inflight)
        {
            bail!("invalid benchmark arguments");
        }
        Ok(())
    }
}

fn parse_number<T>(name: &str, value: &str) -> Result<T>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    value
        .parse()
        .map_err(|error| anyhow!("invalid value {value:?} for -{name}: {error}"))
}

fn parse_duration(name: &str, value: &str) -> Result<Duration> {
    if value == "0" {
        return Ok(Duration::ZERO);
    }
    let duration = humantime::parse_duration(value)
        .map_err(|error| anyhow!("invalid value {value:?} for -{name}: {error}"))?;
    if duration.as_nanos() > i64::MAX as u128 {
        bail!("invalid value {value:?} for -{name}: duration out of range");
    }
    Ok(duration)
}

fn parse_bool(value: &str) -> Result<bool> {
    value
        .parse()
        .map_err(|_| anyhow!("invalid boolean value {value:?} for -require-auto-mtu"))
}

fn usage() {
    eprintln!(
        "Usage of porta-loadgen:
  -clients int
        concurrent tunnel clients (default 1)
  -duration duration
        measured duration (default 6s)
  -inflight int
        maximum outstanding packets per tunnel (default 1)
  -payload int
        IPv4 packet size (default 1200)
  -require-auto-mtu
        require HTTP/3 automatic MTU selection
  -transport string
        transport: h2, h3, or auto (default \"h2\")
  -url string
        benchmark server URL (default \"https://127.0.0.1:18443\")
  -warmup duration
        warmup duration (default 2s)"
    );
}

#[derive(Serialize)]
struct Output {
    clients: usize,
    duration_ms: i64,
    warmup_ms: i64,
    operations: u64,
    operations_per_second: f64,
    gigabits_per_second: f64,
    latency_p50_us: f64,
    latency_p95_us: f64,
    latency_p99_us: f64,
    connect_ms: i64,
    payload_bytes: usize,
    transport: String,
    selected_transport: String,
    mtu: u16,
    mtu_automatic: bool,
    inflight: usize,
    gomaxprocs: usize,
    sampled_latencies: usize,
}

#[derive(Debug, PartialEq)]
struct Metrics {
    operations_per_second: f64,
    gigabits_per_second: f64,
    latency_p50_us: f64,
    latency_p95_us: f64,
    latency_p99_us: f64,
}

fn calculate_metrics(
    operations: u64,
    duration: Duration,
    payload: usize,
    latencies: &mut [u64],
) -> Metrics {
    latencies.sort_unstable();
    let seconds = duration.as_secs_f64();
    Metrics {
        operations_per_second: operations as f64 / seconds,
        gigabits_per_second: operations as f64 * (payload * 2) as f64 * 8.0 / seconds / 1e9,
        latency_p50_us: percentile(latencies, 0.50),
        latency_p95_us: percentile(latencies, 0.95),
        latency_p99_us: percentile(latencies, 0.99),
    }
}

fn percentile(values: &[u64], quantile: f64) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    let index = ((values.len() - 1) as f64 * quantile) as usize;
    values[index] as f64 / 1000.0
}

#[derive(Clone, Copy)]
struct PendingPacket {
    started: Instant,
    measured: bool,
    sampled: bool,
}

struct WorkerResult {
    operations: u64,
    latencies: Vec<u64>,
}

fn main() -> ExitCode {
    let arguments = match Arguments::parse() {
        Ok(ParseOutcome::Run(arguments)) => arguments,
        Ok(ParseOutcome::Help) => {
            usage();
            return ExitCode::SUCCESS;
        }
        Err(error) => {
            eprintln!("{error}");
            usage();
            return ExitCode::from(2);
        }
    };
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(reported_parallelism())
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("create async runtime: {error}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(run(arguments)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run(arguments: Arguments) -> Result<()> {
    let cancellation = CancellationToken::new();
    let signal_cancellation = cancellation.clone();
    let signal_task = tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            signal_cancellation.cancel();
        }
    });

    let connect_started = Instant::now();
    let connections = connect_all(&arguments, &cancellation).await?;
    validate_connections(&connections, &arguments).await?;
    let connect_elapsed = connect_started.elapsed();

    let first = connections
        .first()
        .context("at least one benchmark connection is required")?;
    let selected_transport = transport_name(first.transport).to_owned();
    let mtu = first.lease.mtu;
    let mtu_automatic = first.mtu_automatic;

    let measure_at = Instant::now() + arguments.warmup;
    let stop_at = measure_at + arguments.duration;
    let start = Arc::new(Barrier::new(arguments.clients + 1));
    let mut workers = JoinSet::new();
    for (worker, connection) in connections.into_iter().enumerate() {
        let start = Arc::clone(&start);
        let worker_cancellation = cancellation.child_token();
        let payload = arguments.payload;
        let inflight = arguments.inflight;
        workers.spawn(async move {
            start.wait().await;
            let result = run_worker(
                worker,
                &connection,
                payload,
                inflight,
                measure_at,
                stop_at,
                &worker_cancellation,
            )
            .await;
            connection.close().await;
            result
        });
    }
    start.wait().await;

    let mut operations = 0_u64;
    let mut latencies = Vec::new();
    let mut first_error = None;
    while let Some(joined) = workers.join_next().await {
        match joined {
            Ok(Ok(result)) => {
                operations += result.operations;
                latencies.extend(result.latencies);
            }
            Ok(Err(error)) => {
                if first_error.is_none() {
                    first_error = Some(error);
                    cancellation.cancel();
                }
            }
            Err(error) => {
                if first_error.is_none() {
                    first_error = Some(anyhow!("benchmark worker failed: {error}"));
                    cancellation.cancel();
                }
            }
        }
    }
    signal_task.abort();
    if let Some(error) = first_error {
        return Err(error);
    }

    let metrics = calculate_metrics(
        operations,
        arguments.duration,
        arguments.payload,
        &mut latencies,
    );
    let output = Output {
        clients: arguments.clients,
        duration_ms: duration_milliseconds(arguments.duration),
        warmup_ms: duration_milliseconds(arguments.warmup),
        operations,
        operations_per_second: metrics.operations_per_second,
        gigabits_per_second: metrics.gigabits_per_second,
        latency_p50_us: metrics.latency_p50_us,
        latency_p95_us: metrics.latency_p95_us,
        latency_p99_us: metrics.latency_p99_us,
        connect_ms: duration_milliseconds(connect_elapsed),
        payload_bytes: arguments.payload,
        transport: arguments.transport,
        selected_transport,
        mtu,
        mtu_automatic,
        inflight: arguments.inflight,
        gomaxprocs: reported_parallelism(),
        sampled_latencies: latencies.len(),
    };
    serde_json::to_writer(std::io::stdout().lock(), &output).context("encode benchmark result")?;
    println!();
    Ok(())
}

async fn connect_all(
    arguments: &Arguments,
    cancellation: &CancellationToken,
) -> Result<Vec<Connection>> {
    let transport = parse_transport(&arguments.transport)?;
    let tls = porta_client::tls::config(None, None, true).context("configure benchmark TLS")?;
    let mut tasks = JoinSet::new();
    for index in 0..arguments.clients {
        let url = arguments.url.clone();
        let tls = Arc::clone(&tls);
        let connection_cancellation = cancellation.child_token();
        tasks.spawn(async move {
            let signing_key = SigningKey::random(&mut OsRng);
            let device_name = format!("benchmark-{index}");
            let proof = Arc::new(move |method: &str, path: &str| {
                porta_client::device::create_proof(
                    &signing_key,
                    &device_name,
                    BENCHMARK_TOKEN,
                    method,
                    path,
                    std::time::SystemTime::now(),
                )
                .map_err(ClientError::permanent)
            });
            let config = tunnel::ClientConfig {
                url,
                token: BENCHMARK_TOKEN.to_owned(),
                transport,
                tls,
                timeout: Duration::from_secs(10),
                dial_address: None,
                proof,
                socket_protector: None,
                cancellation: connection_cancellation,
            };
            (index, tunnel::connect(config).await)
        });
    }

    let mut connections: Vec<Option<Connection>> = (0..arguments.clients).map(|_| None).collect();
    let mut first_error = None;
    while let Some(joined) = tasks.join_next().await {
        match joined {
            Ok((index, Ok(connection))) => connections[index] = Some(connection),
            Ok((index, Err(error))) if first_error.is_none() => {
                first_error = Some(anyhow!("connect client {index}: {error}"));
            }
            Ok((_index, Err(_error))) => {}
            Err(error) if first_error.is_none() => {
                first_error = Some(anyhow!("connect client task failed: {error}"));
            }
            Err(_) => {}
        }
    }
    if let Some(error) = first_error {
        cancellation.cancel();
        close_connections(connections.into_iter().flatten()).await;
        return Err(error);
    }
    connections
        .into_iter()
        .enumerate()
        .map(|(index, connection)| {
            connection.ok_or_else(|| anyhow!("connect client {index}: no connection returned"))
        })
        .collect()
}

async fn validate_connections(connections: &[Connection], arguments: &Arguments) -> Result<()> {
    for (index, connection) in connections.iter().enumerate() {
        if arguments.require_auto_mtu
            && connection.transport == Transport::Http3
            && !connection.mtu_automatic
        {
            close_connection_slice(connections).await;
            bail!("client {index} did not negotiate automatic MTU");
        }
        if arguments.require_auto_mtu
            && arguments.transport == "auto"
            && connection.transport != Transport::Http3
        {
            let selected = transport_name(connection.transport);
            close_connection_slice(connections).await;
            bail!("client {index} automatic transport selected {selected}, want HTTP/3");
        }
    }
    Ok(())
}

async fn close_connection_slice(connections: &[Connection]) {
    for connection in connections {
        connection.close().await;
    }
}

async fn close_connections(connections: impl Iterator<Item = Connection>) {
    for connection in connections {
        connection.close().await;
    }
}

fn parse_transport(value: &str) -> Result<Transport> {
    match value {
        "h2" => Ok(Transport::Http2),
        "h3" => Ok(Transport::Http3),
        "auto" => Ok(Transport::Auto),
        _ => bail!("unknown transport {value:?}"),
    }
}

fn transport_name(transport: Transport) -> &'static str {
    match transport {
        Transport::Http2 => "h2",
        Transport::Http3 => "h3",
        Transport::Auto => "auto",
    }
}

async fn run_worker(
    worker: usize,
    connection: &Connection,
    payload: usize,
    inflight: usize,
    measure_at: Instant,
    stop_at: Instant,
    cancellation: &CancellationToken,
) -> Result<WorkerResult> {
    let template = benchmark_packet(connection.lease.address.addr(), payload, worker);
    let mut latencies = Vec::with_capacity(8192);
    let mut pending = HashMap::with_capacity(inflight);
    let mut sequence = 0_u64;

    while pending.len() < inflight && Instant::now() < stop_at {
        send_next(
            connection,
            &template,
            worker,
            measure_at,
            cancellation,
            &mut pending,
            &mut sequence,
        )
        .await?;
    }

    let mut operations = 0_u64;
    while !pending.is_empty() {
        let response = tokio::select! {
            _ = cancellation.cancelled() => bail!("client {worker} cancelled"),
            result = timeout(RECEIVE_TIMEOUT, connection.receive()) => {
                match result {
                    Ok(Ok(response)) => response,
                    Ok(Err(error)) => return Err(anyhow!("client {worker} receive: {error}")),
                    Err(_) => bail!("client {worker} receive timed out after packet loss"),
                }
            }
        };
        if response.len() != template.len() {
            bail!(
                "client {worker} response length {}, want {}",
                response.len(),
                template.len()
            );
        }
        let response_sequence = u64::from_be_bytes(
            response[28..36]
                .try_into()
                .expect("validated packet length is at least 36 bytes"),
        );
        let sent = pending.remove(&response_sequence).ok_or_else(|| {
            anyhow!("client {worker} received unknown response sequence {response_sequence}")
        })?;
        let finished = Instant::now();
        if sent.measured && finished < stop_at {
            operations += 1;
            if sent.sampled {
                latencies.push(finished.duration_since(sent.started).as_nanos() as u64);
            }
        }
        if finished < stop_at {
            send_next(
                connection,
                &template,
                worker,
                measure_at,
                cancellation,
                &mut pending,
                &mut sequence,
            )
            .await?;
        }
    }

    Ok(WorkerResult {
        operations,
        latencies,
    })
}

#[allow(clippy::too_many_arguments)]
async fn send_next(
    connection: &Connection,
    template: &[u8],
    worker: usize,
    measure_at: Instant,
    cancellation: &CancellationToken,
    pending: &mut HashMap<u64, PendingPacket>,
    sequence: &mut u64,
) -> Result<()> {
    let current = *sequence;
    let packet = packet_for_sequence(template, worker, current);
    let started = Instant::now();
    tokio::select! {
        _ = cancellation.cancelled() => bail!("client {worker} cancelled"),
        result = connection.send(&packet) => {
            result.map_err(|error| anyhow!("client {worker} send: {error}"))?;
        }
    }
    pending.insert(
        current,
        PendingPacket {
            started,
            measured: started >= measure_at,
            sampled: current & 7 == 0,
        },
    );
    *sequence += 1;
    Ok(())
}

fn packet_for_sequence(template: &[u8], worker: usize, sequence: u64) -> Vec<u8> {
    let mut packet = template.to_vec();
    let worker_offset = (worker as u64).wrapping_mul(257);
    let destination_port = 1024 + sequence.wrapping_add(worker_offset) % 60000;
    packet[22..24].copy_from_slice(&(destination_port as u16).to_be_bytes());
    packet[28..36].copy_from_slice(&sequence.to_be_bytes());
    packet
}

fn benchmark_packet(source: Ipv4Addr, size: usize, worker: usize) -> Vec<u8> {
    let mut packet = vec![0_u8; size];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(size as u16).to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&source.octets());
    packet[16..20].copy_from_slice(&[1, 1, 1, 1]);
    let source_port = (20000 + worker % 40000) as u16;
    packet[20..22].copy_from_slice(&source_port.to_be_bytes());
    packet[22..24].copy_from_slice(&443_u16.to_be_bytes());
    packet[24..26].copy_from_slice(&((size - 20) as u16).to_be_bytes());
    porta_wire::ip::set_ipv4_header_checksum(&mut packet)
        .expect("benchmark packet always contains a valid IPv4 header");
    packet
}

fn duration_milliseconds(duration: Duration) -> i64 {
    i64::try_from(duration.as_millis()).unwrap_or(i64::MAX)
}

fn reported_parallelism() -> usize {
    let available = std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(1);
    reported_parallelism_from(env::var("GOMAXPROCS").ok().as_deref(), available)
}

fn reported_parallelism_from(gomaxprocs: Option<&str>, available: usize) -> usize {
    gomaxprocs
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(available)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(arguments: &[&str]) -> Result<Arguments> {
        let values = std::iter::once("porta-loadgen")
            .chain(arguments.iter().copied())
            .map(OsString::from);
        match Arguments::parse_from(values)? {
            ParseOutcome::Run(arguments) => Ok(arguments),
            ParseOutcome::Help => bail!("unexpected help"),
        }
    }

    #[test]
    fn packet_matches_go_shape_and_worker_identity() {
        let source = Ipv4Addr::new(10, 66, 0, 9);
        let packet = benchmark_packet(source, 1200, 40001);
        let parsed = porta_wire::ip::parse_ipv4(&packet).unwrap();

        assert_eq!(parsed.source, source);
        assert_eq!(parsed.destination, Ipv4Addr::new(1, 1, 1, 1));
        assert_eq!(parsed.total_length, 1200);
        assert_eq!(packet[0], 0x45);
        assert_eq!(packet[8], 64);
        assert_eq!(packet[9], 17);
        assert_eq!(
            u16::from_be_bytes(packet[20..22].try_into().unwrap()),
            20001
        );
        assert_eq!(u16::from_be_bytes(packet[22..24].try_into().unwrap()), 443);
        assert_eq!(u16::from_be_bytes(packet[24..26].try_into().unwrap()), 1180);
        assert_eq!(porta_wire::ip::ipv4_header_checksum(&packet).unwrap(), 0);
        assert!(packet[26..].iter().all(|byte| *byte == 0));

        let packet = packet_for_sequence(&packet, 3, 9);
        assert_eq!(u16::from_be_bytes(packet[22..24].try_into().unwrap()), 1804);
        assert_eq!(u64::from_be_bytes(packet[28..36].try_into().unwrap()), 9);
        assert_eq!(porta_wire::ip::ipv4_header_checksum(&packet).unwrap(), 0);
    }

    #[test]
    fn go_style_flags_and_validation_are_preserved() {
        let arguments = parse(&[
            "-url=https://gateway.example:443",
            "-clients",
            "4",
            "--duration=1500ms",
            "-warmup",
            "0",
            "-payload",
            "36",
            "-transport",
            "auto",
            "-require-auto-mtu=false",
            "-inflight",
            "256",
        ])
        .unwrap();

        assert_eq!(arguments.url, "https://gateway.example:443");
        assert_eq!(arguments.clients, 4);
        assert_eq!(arguments.duration, Duration::from_millis(1500));
        assert_eq!(arguments.warmup, Duration::ZERO);
        assert_eq!(arguments.payload, 36);
        assert_eq!(arguments.transport, "auto");
        assert!(!arguments.require_auto_mtu);
        assert_eq!(arguments.inflight, 256);
        assert!(parse(&["-clients=0"]).is_err());
        assert!(parse(&["-duration=0"]).is_err());
        assert!(parse(&["-payload=35"]).is_err());
        assert!(parse(&["-payload=1401"]).is_err());
        assert!(parse(&["-inflight=257"]).is_err());
        assert!(parse(&["-duration=300y"]).is_err());
    }

    #[test]
    fn metrics_use_go_sampling_percentiles_and_bidirectional_bytes() {
        let mut latencies = vec![4000, 1000, 3000, 2000];
        let metrics = calculate_metrics(100, Duration::from_secs(2), 1200, &mut latencies);

        assert_eq!(latencies, [1000, 2000, 3000, 4000]);
        assert_eq!(metrics.operations_per_second, 50.0);
        assert_eq!(metrics.gigabits_per_second, 0.00096);
        assert_eq!(metrics.latency_p50_us, 2.0);
        assert_eq!(metrics.latency_p95_us, 3.0);
        assert_eq!(metrics.latency_p99_us, 3.0);
        assert_eq!(percentile(&[], 0.5), 0.0);
    }

    #[test]
    fn gomaxprocs_schema_value_prefers_compatible_environment_setting() {
        assert_eq!(reported_parallelism_from(Some("8"), 4), 8);
        assert_eq!(reported_parallelism_from(Some("0"), 4), 4);
        assert_eq!(reported_parallelism_from(Some("invalid"), 4), 4);
        assert_eq!(duration_milliseconds(Duration::from_micros(1999)), 1);
    }

    #[test]
    fn output_json_schema_matches_go_loadgen() {
        let output = Output {
            clients: 1,
            duration_ms: 6000,
            warmup_ms: 2000,
            operations: 10,
            operations_per_second: 2.0,
            gigabits_per_second: 0.1,
            latency_p50_us: 1.0,
            latency_p95_us: 2.0,
            latency_p99_us: 3.0,
            connect_ms: 4,
            payload_bytes: 1200,
            transport: "auto".to_owned(),
            selected_transport: "h3".to_owned(),
            mtu: 1400,
            mtu_automatic: true,
            inflight: 8,
            gomaxprocs: 4,
            sampled_latencies: 5,
        };
        let value = serde_json::to_value(output).unwrap();
        let mut keys = value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "clients",
                "connect_ms",
                "duration_ms",
                "gigabits_per_second",
                "gomaxprocs",
                "inflight",
                "latency_p50_us",
                "latency_p95_us",
                "latency_p99_us",
                "mtu",
                "mtu_automatic",
                "operations",
                "operations_per_second",
                "payload_bytes",
                "sampled_latencies",
                "selected_transport",
                "transport",
                "warmup_ms",
            ]
        );
    }
}
