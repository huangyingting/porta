//! Access rules: a destination prefix, optionally narrowed to a protocol and
//! a port range, such as `10.1.2.3/32 tcp/443`, `10.0.0.0/8 udp/53`,
//! `10.2.0.0/16 tcp/8000-8100` or `10.3.0.0/16 icmp`.
//!
//! The gateway filters packets without tracking connections, so rules
//! narrowed to ports only decide which connections a device may open:
//! - a TCP rule matches segments that open a connection (SYN without
//!   ACK) to one of its ports; later segments of any connection need only
//!   the address to be allowed, so replies flow;
//! - a UDP rule matches datagrams with one of its ports at either end, so
//!   replies from the service match too;
//! - ICMP errors and fragments after the first need only the address.

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use ipnet::IpNet;
use porta_wire::ip::Transport;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Protocol {
    Any,
    Tcp,
    Udp,
    Icmp,
}

/// One allow or deny entry of an access policy.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AccessRule {
    pub prefix: IpNet,
    pub protocol: Protocol,
    /// Inclusive port range, for TCP and UDP; `None` is every port.
    pub ports: Option<(u16, u16)>,
}

impl AccessRule {
    /// Whether the rule covers every packet to its prefix.
    pub fn is_whole(&self) -> bool {
        self.protocol == Protocol::Any
    }

    /// The rule with its prefix's host bits cleared.
    pub fn trunc(&self) -> Self {
        Self {
            prefix: self.prefix.trunc(),
            ..*self
        }
    }

    /// Whether a packet to `destination` matches the rule.
    pub fn matches(&self, destination: IpAddr, transport: &Transport) -> bool {
        if !self.prefix.contains(&destination) {
            return false;
        }
        let in_range = |port: u16| {
            self.ports
                .is_none_or(|(first, last)| (first..=last).contains(&port))
        };
        match self.protocol {
            Protocol::Any => true,
            Protocol::Icmp => matches!(transport.protocol, 1 | 58),
            Protocol::Tcp => {
                transport.protocol == 6
                    && transport
                        .ports
                        .is_some_and(|(_, destination)| in_range(destination))
            }
            Protocol::Udp => {
                transport.protocol == 17
                    && transport.ports.is_some_and(|(source, destination)| {
                        in_range(source) || in_range(destination)
                    })
            }
        }
    }
}

impl From<IpNet> for AccessRule {
    fn from(prefix: IpNet) -> Self {
        Self {
            prefix,
            protocol: Protocol::Any,
            ports: None,
        }
    }
}

impl From<ipnet::Ipv4Net> for AccessRule {
    fn from(prefix: ipnet::Ipv4Net) -> Self {
        IpNet::V4(prefix).into()
    }
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
#[error("{0:?} is not an access rule; use PREFIX, or PREFIX tcp|udp[/PORT[-PORT]], or PREFIX icmp")]
pub struct RuleError(pub String);

impl FromStr for AccessRule {
    type Err = RuleError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let invalid = || RuleError(value.to_owned());
        let mut parts = value.split_whitespace();
        let address = parts.next().ok_or_else(invalid)?;
        let prefix = address
            .parse::<IpNet>()
            .or_else(|_| address.parse::<IpAddr>().map(IpNet::from))
            .map_err(|_| invalid())?;
        let Some(service) = parts.next() else {
            return Ok(prefix.into());
        };
        if parts.next().is_some() {
            return Err(invalid());
        }
        let (name, ports) = match service.split_once('/') {
            Some((name, ports)) => (name, Some(ports)),
            None => (service, None),
        };
        let protocol = match name.to_ascii_lowercase().as_str() {
            "tcp" => Protocol::Tcp,
            "udp" => Protocol::Udp,
            "icmp" if ports.is_none() => Protocol::Icmp,
            _ => return Err(invalid()),
        };
        let ports = ports
            .map(|ports| {
                let (first, last) = ports.split_once('-').unwrap_or((ports, ports));
                let first = first.parse::<u16>().map_err(|_| invalid())?;
                let last = last.parse::<u16>().map_err(|_| invalid())?;
                if first == 0 || first > last {
                    return Err(invalid());
                }
                Ok((first, last))
            })
            .transpose()?;
        Ok(Self {
            prefix,
            protocol,
            ports,
        })
    }
}

impl fmt::Display for AccessRule {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.prefix)?;
        let name = match self.protocol {
            Protocol::Any => return Ok(()),
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
            Protocol::Icmp => "icmp",
        };
        write!(formatter, " {name}")?;
        match self.ports {
            Some((first, last)) if first == last => write!(formatter, "/{first}"),
            Some((first, last)) => write!(formatter, "/{first}-{last}"),
            None => Ok(()),
        }
    }
}

impl Serialize for AccessRule {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for AccessRule {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tcp(source: u16, destination: u16, flags: u8) -> Transport {
        Transport {
            protocol: 6,
            ports: Some((source, destination)),
            tcp_flags: Some(flags),
            ..Transport::default()
        }
    }

    #[test]
    fn rules_parse_print_and_reject_malformed_input() {
        for (text, printed) in [
            ("10.0.0.0/8", "10.0.0.0/8"),
            ("10.1.2.3", "10.1.2.3/32"),
            ("10.1.2.3/32 tcp/443", "10.1.2.3/32 tcp/443"),
            ("10.0.0.0/8  UDP/53", "10.0.0.0/8 udp/53"),
            ("10.2.0.0/16 tcp/8000-8100", "10.2.0.0/16 tcp/8000-8100"),
            ("10.3.0.0/16 icmp", "10.3.0.0/16 icmp"),
            ("fd66::/64 tcp", "fd66::/64 tcp"),
        ] {
            assert_eq!(
                text.parse::<AccessRule>().unwrap().to_string(),
                printed,
                "{text}"
            );
        }
        for invalid in [
            "",
            "nonsense",
            "10.0.0.0/8 sctp",
            "10.0.0.0/8 tcp/0",
            "10.0.0.0/8 tcp/90-80",
            "10.0.0.0/8 tcp/70000",
            "10.0.0.0/8 icmp/8",
            "10.0.0.0/8 tcp/443 extra",
        ] {
            assert!(invalid.parse::<AccessRule>().is_err(), "{invalid}");
        }
        let rule: AccessRule = serde_json::from_str("\"10.1.2.3/32 tcp/22\"").unwrap();
        assert_eq!(
            serde_json::to_string(&rule).unwrap(),
            "\"10.1.2.3/32 tcp/22\""
        );
    }

    #[test]
    fn rules_match_protocols_ports_and_prefixes() {
        let address: IpAddr = "10.1.2.3".parse().unwrap();
        let https: AccessRule = "10.1.2.0/24 tcp/443".parse().unwrap();
        assert!(https.matches(address, &tcp(40_000, 443, Transport::TCP_SYN)));
        assert!(!https.matches(address, &tcp(40_000, 22, Transport::TCP_SYN)));
        assert!(!https.matches("10.9.9.9".parse().unwrap(), &tcp(1, 443, 0)));
        let dns: AccessRule = "10.1.2.0/24 udp/53".parse().unwrap();
        let udp = |source, destination| Transport {
            protocol: 17,
            ports: Some((source, destination)),
            ..Transport::default()
        };
        assert!(dns.matches(address, &udp(50_000, 53)));
        assert!(dns.matches(address, &udp(53, 50_000)));
        assert!(!dns.matches(address, &udp(50_000, 54)));
        let ping: AccessRule = "10.1.2.0/24 icmp".parse().unwrap();
        assert!(ping.matches(
            address,
            &Transport {
                protocol: 1,
                ..Transport::default()
            }
        ));
        assert!(!ping.matches(address, &udp(1, 1)));
        assert!(
            AccessRule::from("10.0.0.0/8".parse::<IpNet>().unwrap()).matches(address, &udp(1, 1))
        );
    }
}
