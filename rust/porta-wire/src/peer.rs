//! Direct paths between devices. A gateway that offers them sets
//! [`PEERS_HEADER`] on the HTTP/3 CONNECT-IP response. The client then sends
//! a PEER_OFFER capsule with the SHA-256 fingerprint of the certificate it
//! presents to other devices, and the gateway answers with PEERS capsules:
//! the devices this one may exchange traffic with, the public UDP address
//! the gateway sees for each, and their certificate fingerprints. The list
//! is complete and replaces the previous one; it is resent when it changes.
//!
//! Devices then connect to each other over QUIC ([`PEER_ALPN`]) from the
//! socket that carries their tunnel, each authenticating the other by the
//! fingerprint the gateway vouched for, and exchange IP packets as QUIC
//! datagrams.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use thiserror::Error;

/// Response header: `?1` when the gateway coordinates direct paths.
pub const PEERS_HEADER: &str = "x-porta-peers";
pub const CAPSULE_PEER_OFFER: u64 = 0xff7010;
pub const CAPSULE_PEERS: u64 = 0xff7011;
/// ALPN of the device-to-device QUIC connections.
pub const PEER_ALPN: &[u8] = b"porta-peer/1";
/// The TLS server name devices use with each other; certificates are
/// checked by fingerprint, not by name.
pub const PEER_SERVER_NAME: &str = "peer.porta.invalid";
pub const MAX_PEERS: usize = 64;
const VERSION: u8 = 1;
const HAS_IPV6: u8 = 1;
const ENDPOINT_IPV6: u8 = 2;

pub type Fingerprint = [u8; 32];

#[derive(Debug, Error, Eq, PartialEq)]
pub enum PeerError {
    #[error("unsupported peer message version {0}")]
    Version(u8),
    #[error("truncated peer message")]
    Truncated,
    #[error("too many peers")]
    TooMany,
    #[error("invalid peer entry")]
    Invalid,
}

/// Another device and how to reach it directly.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Peer {
    /// Its tunnel addresses.
    pub address: Ipv4Addr,
    /// Only when both devices have IPv6.
    pub address6: Option<Ipv6Addr>,
    /// Its public UDP address as the gateway sees it.
    pub endpoint: SocketAddr,
    pub fingerprint: Fingerprint,
}

pub fn encode_offer(fingerprint: &Fingerprint) -> Vec<u8> {
    let mut value = Vec::with_capacity(33);
    value.push(VERSION);
    value.extend_from_slice(fingerprint);
    value
}

pub fn decode_offer(value: &[u8]) -> Result<Fingerprint, PeerError> {
    match value.split_first() {
        Some((&VERSION, rest)) => rest.try_into().map_err(|_| PeerError::Truncated),
        Some((&version, _)) => Err(PeerError::Version(version)),
        None => Err(PeerError::Truncated),
    }
}

pub fn encode_peers(peers: &[Peer]) -> Result<Vec<u8>, PeerError> {
    if peers.len() > MAX_PEERS {
        return Err(PeerError::TooMany);
    }
    let mut value = vec![VERSION, peers.len() as u8];
    for peer in peers {
        let mut flags = 0;
        if peer.address6.is_some() {
            flags |= HAS_IPV6;
        }
        if peer.endpoint.is_ipv6() {
            flags |= ENDPOINT_IPV6;
        }
        value.extend_from_slice(&peer.address.octets());
        value.push(flags);
        if let Some(address6) = peer.address6 {
            value.extend_from_slice(&address6.octets());
        }
        match peer.endpoint.ip() {
            IpAddr::V4(address) => value.extend_from_slice(&address.octets()),
            IpAddr::V6(address) => value.extend_from_slice(&address.octets()),
        }
        value.extend_from_slice(&peer.endpoint.port().to_be_bytes());
        value.extend_from_slice(&peer.fingerprint);
    }
    Ok(value)
}

pub fn decode_peers(value: &[u8]) -> Result<Vec<Peer>, PeerError> {
    let mut input = Reader(value);
    match input.byte()? {
        VERSION => {}
        version => return Err(PeerError::Version(version)),
    }
    let count = usize::from(input.byte()?);
    if count > MAX_PEERS {
        return Err(PeerError::TooMany);
    }
    let mut peers = Vec::with_capacity(count);
    for _ in 0..count {
        let address = Ipv4Addr::from(input.array::<4>()?);
        let flags = input.byte()?;
        if flags & !(HAS_IPV6 | ENDPOINT_IPV6) != 0 {
            return Err(PeerError::Invalid);
        }
        let address6 = (flags & HAS_IPV6 != 0)
            .then(|| input.array::<16>().map(Ipv6Addr::from))
            .transpose()?;
        let ip = if flags & ENDPOINT_IPV6 != 0 {
            IpAddr::V6(Ipv6Addr::from(input.array::<16>()?))
        } else {
            IpAddr::V4(Ipv4Addr::from(input.array::<4>()?))
        };
        let port = u16::from_be_bytes(input.array::<2>()?);
        let fingerprint = input.array::<32>()?;
        if port == 0 || ip.is_unspecified() || ip.is_multicast() {
            return Err(PeerError::Invalid);
        }
        peers.push(Peer {
            address,
            address6,
            endpoint: SocketAddr::new(ip, port),
            fingerprint,
        });
    }
    if !input.0.is_empty() {
        return Err(PeerError::Invalid);
    }
    Ok(peers)
}

struct Reader<'a>(&'a [u8]);

impl Reader<'_> {
    fn byte(&mut self) -> Result<u8, PeerError> {
        Ok(self.array::<1>()?[0])
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], PeerError> {
        let (head, rest) = self.0.split_at_checked(N).ok_or(PeerError::Truncated)?;
        self.0 = rest;
        Ok(head.try_into().expect("split at N"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_lists_round_trip_and_reject_malformed_input() {
        let peers = vec![
            Peer {
                address: Ipv4Addr::new(10, 66, 0, 3),
                address6: Some("fd66::3".parse().unwrap()),
                endpoint: "198.51.100.20:40000".parse().unwrap(),
                fingerprint: [7; 32],
            },
            Peer {
                address: Ipv4Addr::new(10, 66, 0, 4),
                address6: None,
                endpoint: "[2001:db8::4]:443".parse().unwrap(),
                fingerprint: [9; 32],
            },
        ];
        let encoded = encode_peers(&peers).unwrap();
        assert_eq!(decode_peers(&encoded).unwrap(), peers);
        assert_eq!(decode_peers(&encode_peers(&[]).unwrap()).unwrap(), vec![]);
        for cut in 0..encoded.len() {
            assert!(decode_peers(&encoded[..cut]).is_err(), "{cut}");
        }
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(decode_peers(&trailing), Err(PeerError::Invalid));
        let mut version = encoded.clone();
        version[0] = 2;
        assert_eq!(decode_peers(&version), Err(PeerError::Version(2)));
        let mut flags = encoded.clone();
        flags[6] |= 0x80;
        assert_eq!(decode_peers(&flags), Err(PeerError::Invalid));
        let mut port = encode_peers(&peers[..1]).unwrap();
        let at = port.len() - 34;
        port[at..at + 2].copy_from_slice(&[0, 0]);
        assert_eq!(decode_peers(&port), Err(PeerError::Invalid));
        assert_eq!(
            encode_peers(&vec![peers[0]; MAX_PEERS + 1]),
            Err(PeerError::TooMany)
        );
    }

    #[test]
    fn offers_carry_one_fingerprint() {
        assert_eq!(decode_offer(&encode_offer(&[5; 32])).unwrap(), [5; 32]);
        assert_eq!(decode_offer(&[1; 32]), Err(PeerError::Truncated));
        assert_eq!(decode_offer(&[2; 33]), Err(PeerError::Version(2)));
        assert_eq!(decode_offer(&[]), Err(PeerError::Truncated));
    }
}
