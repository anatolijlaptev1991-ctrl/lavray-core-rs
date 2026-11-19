// SPDX-License-Identifier: GPL-3.0-only

//! FakeIP-пул (порт dns/fakeip): двунаправленное отображение
//! домен ↔ виртуальный IP из CIDR; персистентность — уровнем выше.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Mutex;

/// Пул виртуальных адресов (IPv4-сеть, seed фиксирован — детерминизм).
pub struct FakeIpPool {
    state: Mutex<State>,
}

struct State {
    domain_to_ip: HashMap<String, Ipv4Addr>,
    ip_to_domain: HashMap<Ipv4Addr, String>,
    /// Следующий адрес (простой инкремент от network+2; .0 и .1 резервы).
    next: u32,
    last: u32,
}

impl FakeIpPool {
    /// Пул из IPv4-CIDR (например `198.18.0.0/15`).
    ///
    /// # Errors
    /// Невалидный CIDR / не IPv4.
    pub fn new(cidr: &str) -> Result<Self, String> {
        let net: crate::cidr::IpnetLike = cidr
            .parse::<crate::cidr::IpnetLike>()
            .map_err(|_| format!("fakeip: invalid cidr {cidr}"))?;
        if !net.is_v4 {
            return Err("fakeip: only ipv4 supported".into());
        }
        let IpAddr::V4(net_v4) = net.network else {
            return Err("fakeip: only ipv4 supported".into());
        };
        let base = u32::from(net_v4);
        let total = match net.prefix {
            0 => u32::MAX,
            32 => 1,
            p => {
                // 2^(32-p), без переполнения
                if p > 31 {
                    2
                } else {
                    u32::try_from(1u64 << (32 - p)).unwrap_or(u32::MAX)
                }
            }
        };
        Ok(Self {
            state: Mutex::new(State {
                domain_to_ip: HashMap::new(),
                ip_to_domain: HashMap::new(),
                next: base + 2, // network и broadcast-границы не выдаём
                last: base.saturating_add(total - 1),
            }),
        })
    }

    /// Выдать/вернуть существующий виртуальный IP для домена.
    #[must_use]
    pub fn get(&self, domain: &str) -> IpAddr {
        let mut st = self.state.lock().expect("fakeip: poisoned");
        if let Some(ip) = st.domain_to_ip.get(domain) {
            return IpAddr::V4(*ip);
        }
        let ip = loop {
            if st.next > st.last {
                st.next = st.last.saturating_sub(1024).max(2);
            }
            let ip = Ipv4Addr::from(st.next);
            st.next += 1;
            if !st.ip_to_domain.contains_key(&ip) {
                break ip;
            }
        };
        st.domain_to_ip.insert(domain.to_string(), ip);
        st.ip_to_domain.insert(ip, domain.to_string());
        IpAddr::V4(ip)
    }

    /// Обратный lookup: домен виртуального IP (None — не из пула).
    #[must_use]
    pub fn lookup(&self, ip: IpAddr) -> Option<String> {
        let IpAddr::V4(v4) = ip else {
            return None;
        };
        self.state
            .lock()
            .expect("fakeip: poisoned")
            .ip_to_domain
            .get(&v4)
            .cloned()
    }

    /// Размер пула (выданных доменов).
    #[must_use]
    pub fn len(&self) -> usize {
        self.state
            .lock()
            .expect("fakeip: poisoned")
            .domain_to_ip
            .len()
    }

    /// Пуст ли пул.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_allocation() {
        let p1 = FakeIpPool::new("198.18.0.0/15").expect("pool");
        let a1 = p1.get("a.com");
        let a2 = p1.get("a.com");
        assert_eq!(a1, a2, "same domain — same ip");
        let p2 = FakeIpPool::new("198.18.0.0/15").expect("pool");
        assert_eq!(p2.get("a.com"), a1, "детерминизм: новый пул выдаёт то же");
        let IpAddr::V4(v4) = a1 else { panic!("v4") };
        // 198.18.0.0/15 — benchmark-сеть (не private), проверяем попадание в CIDR
        let octets = v4.octets();
        assert_eq!(octets[0], 198);
        assert_eq!(octets[1], 18);
    }

    #[test]
    fn reverse_lookup() {
        let pool = FakeIpPool::new("198.18.0.0/15").expect("pool");
        let ip = pool.get("b.com");
        assert_eq!(pool.lookup(ip).as_deref(), Some("b.com"));
        assert_eq!(pool.lookup("8.8.8.8".parse().unwrap()), None);
        assert_eq!(pool.lookup("2001:db8::1".parse().unwrap()), None);
    }

    #[test]
    fn wraps_on_exhaustion() {
        let pool = FakeIpPool::new("198.18.0.1/32").expect("pool");
        let a = pool.get("x.com");
        let b = pool.get("y.com");
        assert_ne!(a, b, "обход занятых адресов");
    }

    #[test]
    fn rejects_bad_cidr() {
        assert!(FakeIpPool::new("nonsense").is_err());
        assert!(FakeIpPool::new("2001:db8::/32").is_err(), "v4 only");
    }
}
