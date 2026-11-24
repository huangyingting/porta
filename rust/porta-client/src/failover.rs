//! Multi-gateway profiles: a profile may list several gateways that share an
//! account registry. Clients measure how quickly each gateway's endpoints
//! accept a TCP connection, try the fastest first, and fail over to the
//! next on errors.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use tokio_util::sync::CancellationToken;

/// How long a latency probe waits for one endpoint.
pub const PROBE_TIMEOUT: Duration = Duration::from_millis(1500);

/// One endpoint of one gateway in a profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Candidate {
    /// Index of the gateway in the profile.
    pub gateway: usize,
    pub address: SocketAddr,
}

/// Measures the TCP connect time of every address concurrently; `None`
/// marks an endpoint that did not answer in time.
pub async fn probe(
    addresses: &[SocketAddr],
    timeout: Duration,
    cancellation: &CancellationToken,
) -> Vec<Option<Duration>> {
    let probes = addresses.iter().map(|address| async move {
        let started = Instant::now();
        match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(address)).await {
            Ok(Ok(_)) => Some(started.elapsed()),
            _ => None,
        }
    });
    tokio::select! {
        _ = cancellation.cancelled() => vec![None; addresses.len()],
        latencies = futures_util::future::join_all(probes) => latencies,
    }
}

/// Orders candidates fastest first. Unreachable endpoints follow in their
/// listed order, so failover still reaches them.
pub fn order(candidates: &[Candidate], latencies: &[Option<Duration>]) -> Vec<Candidate> {
    let mut indexed = candidates.iter().copied().enumerate().collect::<Vec<_>>();
    indexed.sort_by_key(|(index, _)| {
        (
            latencies.get(*index).copied().flatten().is_none(),
            latencies.get(*index).copied().flatten(),
            *index,
        )
    });
    indexed
        .into_iter()
        .map(|(_, candidate)| candidate)
        .collect()
}

/// A human-readable summary of a probe, fastest first.
pub fn describe(
    candidates: &[Candidate],
    latencies: &[Option<Duration>],
    gateway_name: impl Fn(usize) -> String,
) -> String {
    order(candidates, latencies)
        .iter()
        .map(|candidate| {
            let index = candidates
                .iter()
                .position(|known| known == candidate)
                .expect("ordered candidates come from the input");
            match latencies.get(index).copied().flatten() {
                Some(latency) => format!(
                    "{} {} ({} ms)",
                    gateway_name(candidate.gateway),
                    candidate.address,
                    latency.as_millis()
                ),
                None => format!(
                    "{} {} (no answer)",
                    gateway_name(candidate.gateway),
                    candidate.address
                ),
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(gateway: usize, port: u16) -> Candidate {
        Candidate {
            gateway,
            address: SocketAddr::from(([127, 0, 0, 1], port)),
        }
    }

    #[test]
    fn faster_endpoints_come_first_and_silent_ones_last() {
        let candidates = [
            candidate(0, 1),
            candidate(1, 2),
            candidate(2, 3),
            candidate(3, 4),
        ];
        let latencies = [
            Some(Duration::from_millis(80)),
            None,
            Some(Duration::from_millis(5)),
            None,
        ];
        assert_eq!(
            order(&candidates, &latencies),
            vec![candidates[2], candidates[0], candidates[1], candidates[3]]
        );
        let summary = describe(&candidates, &latencies, |gateway| format!("g{gateway}"));
        assert!(
            summary.starts_with("g2 127.0.0.1:3 (5 ms), g0"),
            "{summary}"
        );
        assert!(summary.ends_with("g3 127.0.0.1:4 (no answer)"), "{summary}");
    }

    #[tokio::test]
    async fn probes_measure_listening_endpoints_and_time_out_others() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let open = listener.local_addr().unwrap();
        // A bound but never accepting socket still completes the handshake,
        // so use a closed port for the unreachable case.
        let closed = {
            let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            socket.local_addr().unwrap()
        };
        let latencies = probe(
            &[open, closed],
            Duration::from_millis(500),
            &CancellationToken::new(),
        )
        .await;
        assert!(latencies[0].is_some());
        assert!(latencies[1].is_none());
        drop(listener);
    }
}
