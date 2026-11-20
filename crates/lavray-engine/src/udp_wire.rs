// SPDX-License-Identifier: GPL-3.0-only

//! Свободные wire-функции UDP datagrams (для UdpPipe и бенчей):
//! hysteria2 udpMessage и tuic v5 CommandPacket — сборка/разбор
//! с дефрагментацией по packetID.

use crate::addr::TargetAddr;
use crate::hy2_config;
use std::collections::HashMap;
use std::io;

/// QUIC-varint длина значения (1/2/4/8).
#[must_use]
pub fn varint_len_val(v: usize) -> usize {
    if v < 64 {
        1
    } else if v < 16_384 {
        2
    } else if v < 1_073_741_824 {
        4
    } else {
        8
    }
}

/// MTU данных hysteria2 UDP: maxPacketSize(1197) − headerSize(dest)
/// (parity Go udpMTU).
#[must_use]
pub fn hy2_udp_mtu(dest: &str) -> usize {
    let header = 8 + varint_len_val(dest.len()) + dest.len();
    (1200_usize - 3).saturating_sub(header)
}

/// Адрес-строка цели «host:port» (parity M.Socksaddr.String()).
#[must_use]
pub fn dest_string(target: &TargetAddr) -> String {
    match target {
        TargetAddr::Domain(d, p) => format!("{d}:{p}"),
        TargetAddr::Ip(ip, p) => format!("{ip}:{p}"),
    }
}

/// Свободная сборка hysteria2 udpMessage (для бенчей и send).
#[must_use]
pub fn pack_hy2_msg(
    session_id: u32,
    packet_id: u16,
    frag_id: u8,
    frag_total: u8,
    dest: &str,
    data: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + 8 + dest.len() + data.len());
    out.extend_from_slice(&session_id.to_be_bytes());
    out.extend_from_slice(&packet_id.to_be_bytes());
    out.push(frag_id);
    out.push(frag_total);
    hy2_config::write_varint(&mut out, dest.len() as u64);
    out.extend_from_slice(dest.as_bytes());
    out.extend_from_slice(data);
    out
}

/// Свободная распаковка hysteria2 udpMessage с дефрагментацией.
///
/// # Errors
/// Короткий/обрезанный datagram.
pub fn unpack_hy2_msg<S: std::hash::BuildHasher>(
    dgram: &[u8],
    frags: &mut HashMap<u16, Vec<(u8, Vec<u8>)>, S>,
) -> io::Result<Option<Vec<u8>>> {
    if dgram.len() < 8 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "hy2 udp: короткий",
        ));
    }
    let pid = u16::from_be_bytes([dgram[4], dgram[5]]);
    let frag_id = dgram[6];
    let frag_total = dgram[7];
    let (dlen, used) = crate::hy2::read_varint(&dgram[8..])
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.0))?;
    let hdr_end = 8 + used + usize::try_from(dlen).unwrap_or(0);
    if dgram.len() < hdr_end {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "hy2 udp: dst обрезан",
        ));
    }
    let data = dgram[hdr_end..].to_vec();
    if frag_total <= 1 {
        return Ok(Some(data));
    }
    let parts = frags.entry(pid).or_default();
    parts.push((frag_id, data));
    if parts.len() == usize::from(frag_total) {
        parts.sort_by_key(|(id, _)| *id);
        let full: Vec<u8> = parts.iter().flat_map(|(_, d)| d.iter().copied()).collect();
        frags.remove(&pid);
        Ok(Some(full))
    } else {
        Ok(None)
    }
}

/// Свободная сборка tuic CommandPacket (для бенчей и send).
///
/// # Errors
/// Пакет > 65535.
pub fn pack_tuic_msg(
    session_id: u16,
    packet_id: u16,
    frag_id: u8,
    frag_total: u8,
    target: &TargetAddr,
    data: &[u8],
) -> io::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(10 + 18 + data.len());
    out.push(5); // version
    out.push(2); // CommandPacket
    out.extend_from_slice(&session_id.to_be_bytes());
    out.extend_from_slice(&packet_id.to_be_bytes());
    out.push(frag_total);
    out.push(frag_id);
    let dlen = u16::try_from(data.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "tuic udp: > 65535"))?;
    out.extend_from_slice(&dlen.to_be_bytes());
    crate::tuic::write_addr_port(&mut out, target);
    out.extend_from_slice(data);
    Ok(out)
}

/// Свободная распаковка tuic CommandPacket с дефрагментацией.
///
/// # Errors
/// Короткий/обрезанный datagram.
pub fn unpack_tuic_msg<S: std::hash::BuildHasher>(
    dgram: &[u8],
    frags: &mut HashMap<u16, Vec<(u8, Vec<u8>)>, S>,
) -> io::Result<Option<Vec<u8>>> {
    if dgram.len() < 10 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "tuic udp: короткий",
        ));
    }
    let pid = u16::from_be_bytes([dgram[2], dgram[3]]);
    let frag_total = dgram[4];
    let frag_id = dgram[5];
    let dlen = u16::from_be_bytes([dgram[8], dgram[9]]) as usize;
    let mut off = 10;
    let addr_len = tuic_addr_port_len(&dgram[off..]);
    if addr_len == 0 || dgram.len() < off + addr_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "tuic addr: ATYP",
        ));
    }
    off += addr_len;
    if dgram.len() < off + dlen {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "tuic udp: data обрезан",
        ));
    }
    let data = dgram[off..off + dlen].to_vec();
    if frag_total <= 1 {
        return Ok(Some(data));
    }
    let parts = frags.entry(pid).or_default();
    parts.push((frag_id, data));
    if parts.len() == usize::from(frag_total) {
        parts.sort_by_key(|(id, _)| *id);
        let full: Vec<u8> = parts.iter().flat_map(|(_, d)| d.iter().copied()).collect();
        frags.remove(&pid);
        Ok(Some(full))
    } else {
        Ok(None)
    }
}

/// Длина ATYP-адреса (tuic: адрес ПЕРЕД портом).
#[must_use]
pub fn tuic_addr_port_len(b: &[u8]) -> usize {
    match b.first() {
        Some(0x00) => usize::from(b.get(1).copied().unwrap_or(255)) + 4,
        Some(0x01) => 7,
        Some(0x02) => 19,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hy2_pack_unpack_roundtrip() {
        let pkt = pack_hy2_msg(0x1122_3344, 9, 0, 1, "1.1.1.1:53", &[1, 2, 3]);
        let mut f = HashMap::new();
        let d = unpack_hy2_msg(&pkt, &mut f).expect("unpack").expect("some");
        assert_eq!(d, [1, 2, 3]);
    }

    #[test]
    fn tuic_pack_unpack_roundtrip() {
        let pkt = pack_tuic_msg(
            0x52cf,
            9,
            0,
            1,
            &TargetAddr::Ip(
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1)),
                53,
            ),
            &[1, 2, 3],
        )
        .expect("pack");
        let mut f = HashMap::new();
        let d = unpack_tuic_msg(&pkt, &mut f)
            .expect("unpack")
            .expect("some");
        assert_eq!(d, [1, 2, 3]);
    }
}
