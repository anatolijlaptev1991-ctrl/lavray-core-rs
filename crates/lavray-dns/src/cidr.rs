// SPDX-License-Identifier: GPL-3.0-only

//! Внутренний разбор CIDR (без внешних крейтов): сеть + префикс.

use std::net::{IpAddr, Ipv4Addr};

/// Внутренний разбор CIDR (IPv4/IPv6-флаг, network, prefix) — без ipnet crate.
pub(crate) struct IpnetLike {
    pub(crate) is_v4: bool,
    pub(crate) network: std::net::IpAddr,
    pub(crate) prefix: u8,
}

impl std::str::FromStr for IpnetLike {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (addr_s, prefix_s) = s
            .split_once('/')
            .ok_or_else(|| format!("invalid cidr {s}"))?;
        let prefix: u8 = prefix_s
            .parse()
            .map_err(|_| format!("bad prefix {prefix_s}"))?;
        let addr: IpAddr = addr_s.parse().map_err(|_| format!("bad addr {addr_s}"))?;
        let max = match addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix > max {
            return Err(format!("prefix {prefix} > {max}"));
        }
        let network = match addr {
            IpAddr::V4(v4) => {
                let bits = u32::from(v4);
                let mask = match prefix {
                    0 => 0,
                    32 => u32::MAX,
                    p => u32::MAX << (32 - p),
                };
                IpAddr::V4(Ipv4Addr::from(bits & mask))
            }
            IpAddr::V6(v6) => {
                let bits = u128::from(v6);
                let mask = match prefix {
                    0 => 0,
                    128 => u128::MAX,
                    p => u128::MAX << (128 - p),
                };
                IpAddr::V6(std::net::Ipv6Addr::from(bits & mask))
            }
        };
        Ok(Self {
            is_v4: matches!(addr, IpAddr::V4(_)),
            network,
            prefix,
        })
    }
}
