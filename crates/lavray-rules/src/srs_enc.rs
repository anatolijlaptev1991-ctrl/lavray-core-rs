// SPDX-License-Identifier: GPL-3.0-only

//! Кодеры элементов .srs: IPSet-диапазоны, адреса, слайсы строк/u16/u64,
//! uvarint (varbin Go).

/// IPSet: version 1 + BE u64 count + пары from/to (без слияния — формат
/// допускает несмёжные диапазоны; чтение идентично).
pub(crate) fn write_ipset<W: std::io::Write>(w: &mut W, cidrs: &[String]) -> std::io::Result<()> {
    w.write_all(&[1])?;
    w.write_all(&(cidrs.len() as u64).to_be_bytes())?;
    for c in cidrs {
        let net: ipnet::IpNet = c.parse().map_err(std::io::Error::other)?;
        let (from, to) = range_of(&net);
        write_addr(w, from)?;
        write_addr(w, to)?;
    }
    Ok(())
}

/// Диапазон сети [network, broadcast].
fn range_of(net: &ipnet::IpNet) -> (std::net::IpAddr, std::net::IpAddr) {
    use std::net::IpAddr;
    match net {
        ipnet::IpNet::V4(n) => {
            let base = u32::from(n.network());
            let broadcast = if n.prefix_len() == 0 {
                u32::MAX
            } else {
                base | u32::MAX.checked_shr(u32::from(n.prefix_len())).unwrap_or(0)
            };
            (
                IpAddr::V4(std::net::Ipv4Addr::from(base)),
                IpAddr::V4(std::net::Ipv4Addr::from(broadcast)),
            )
        }
        ipnet::IpNet::V6(n) => {
            let base = u128::from(n.network());
            let broadcast = if n.prefix_len() == 0 {
                u128::MAX
            } else {
                base | u128::MAX
                    .checked_shr(u32::from(n.prefix_len()))
                    .unwrap_or(0)
            };
            (
                IpAddr::V6(std::net::Ipv6Addr::from(base)),
                IpAddr::V6(std::net::Ipv6Addr::from(broadcast)),
            )
        }
    }
}

fn write_addr<W: std::io::Write>(w: &mut W, a: std::net::IpAddr) -> std::io::Result<()> {
    match a {
        std::net::IpAddr::V4(v) => {
            write_uvarint(w, 4)?;
            w.write_all(&v.octets())?;
        }
        std::net::IpAddr::V6(v) => {
            write_uvarint(w, 16)?;
            w.write_all(&v.octets())?;
        }
    }
    Ok(())
}

pub(crate) fn write_string_slice<W: std::io::Write>(
    w: &mut W,
    values: &[String],
) -> std::io::Result<()> {
    write_uvarint(w, values.len() as u64)?;
    for s in values {
        write_uvarint(w, s.len() as u64)?;
        w.write_all(s.as_bytes())?;
    }
    Ok(())
}

pub(crate) fn write_u16_slice<W: std::io::Write>(
    w: &mut W,
    values: &[String],
) -> std::io::Result<()> {
    write_uvarint(w, values.len() as u64)?;
    for v in values {
        let n: u16 = v.parse().map_err(std::io::Error::other)?;
        w.write_all(&n.to_be_bytes())?;
    }
    Ok(())
}

pub(crate) fn write_u64_slice<W: std::io::Write>(w: &mut W, values: &[u64]) -> std::io::Result<()> {
    write_uvarint(w, values.len() as u64)?;
    for v in values {
        w.write_all(&v.to_be_bytes())?;
    }
    Ok(())
}

pub(crate) fn write_uvarint<W: std::io::Write>(w: &mut W, mut v: u64) -> std::io::Result<()> {
    loop {
        if v < 0x80 {
            // значение < 0x80 — безопасное сужение по смыслу uvarint
            return w.write_all(&[u8::try_from(v).unwrap_or_default()]);
        }
        w.write_all(&[(v & 0x7f) as u8 | 0x80])?;
        v >>= 7;
    }
}
