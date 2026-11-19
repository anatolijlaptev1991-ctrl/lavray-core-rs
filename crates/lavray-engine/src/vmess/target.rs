// SPDX-License-Identifier: GPL-3.0-only

//! Разбор адреса VMess-заголовка (ПОРТ ПЕРЕД адресом, PortThenAddress).

use crate::addr::TargetAddr;

/// Адрес VMess: ПОРТ ПЕРЕД адресом (PortThenAddress).
pub(super) fn parse_addr(b: &[u8]) -> std::io::Result<(TargetAddr, usize)> {
    if b.len() < 3 {
        return Err(std::io::Error::other("vmess: адрес короткий"));
    }
    let port = u16::from_be_bytes([b[0], b[1]]);
    let mut used = 2usize;
    let t = match b[2] {
        0x01 if b.len() >= 7 => {
            let o: [u8; 4] = b[3..7].try_into().expect("4");
            used += 5;
            TargetAddr::Ip(std::net::IpAddr::V4(o.into()), port)
        }
        0x02 => {
            let l = *b
                .get(3)
                .ok_or_else(|| std::io::Error::other("vmess: fqdn"))? as usize;
            if b.len() < 4 + l {
                return Err(std::io::Error::other("vmess: fqdn короткий"));
            }
            let d = std::str::from_utf8(&b[4..4 + l])
                .map_err(|_| std::io::Error::other("vmess: fqdn utf8"))?;
            used += 2 + l;
            TargetAddr::Domain(d.to_string(), port)
        }
        0x03 if b.len() >= 19 => {
            let o: [u8; 16] = b[3..19].try_into().expect("16");
            used += 17;
            TargetAddr::Ip(std::net::IpAddr::V6(o.into()), port)
        }
        _ => return Err(std::io::Error::other("vmess: ATYP")),
    };
    Ok((t, used))
}
