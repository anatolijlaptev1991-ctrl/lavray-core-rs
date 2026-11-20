// SPDX-License-Identifier: GPL-3.0-only

//! TUIC v5 UDP-канал: QUIC datagrams CommandPacket (session u16/packet
//! u16/фрагменты/dataLen/AddrPort), паритет sing-quic tuic packet.go.

use crate::addr::TargetAddr;
use crate::tuic::TuicConfig;
use crate::udp_pipe::UdpPipe;
use std::collections::HashMap;
use std::io;

/// TUIC v5 UDP-канал (QUIC datagrams CommandPacket, session u16).
pub struct TuicUdp {
    conn: quinn::Connection,
    session_id: u16,
    packet_id: u16,
    /// Сборка фрагментов: (packet_id) → [(frag_id, data)].
    frags: HashMap<u16, Vec<(u8, Vec<u8>)>>,
}

/// Подключить TUIC UDP-канал (QUIC + auth + datagrams CommandPacket).
///
/// # Errors
/// I/O / TLS / auth.
pub async fn tuic_connect(cfg: &TuicConfig, target: &TargetAddr) -> io::Result<UdpPipe> {
    let uuid = crate::tuic::parse_uuid(&cfg.uuid)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.0))?;
    let server = crate::hy2_conn::resolve_server(&cfg.server, cfg.server_port)
        .await
        .map_err(std::io::Error::other)?;
    let conn = crate::tuic_conn::establish(cfg, server, &uuid)
        .await
        .map_err(std::io::Error::other)?;
    Ok(UdpPipe::Tuic(
        TuicUdp {
            conn,
            session_id: crate::udp_pipe_hy2::rand_u16(),
            packet_id: 0,
            frags: HashMap::new(),
        },
        target.clone(),
    ))
}

impl TuicUdp {
    pub(crate) async fn send(&mut self, data: &[u8], target: &TargetAddr) -> io::Result<()> {
        let addr_len = addr_port_len_of(target)?;
        let mtu = (1200_usize).saturating_sub(10 + addr_len);
        if mtu == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "tuic udp: слишком длинный адрес",
            ));
        }
        self.packet_id = self.packet_id.wrapping_add(1);
        let pid = self.packet_id;
        if data.len() <= mtu {
            let pkt = self.pack_frag(pid, 0, 1, target, data)?;
            self.conn
                .send_datagram_wait(pkt.into())
                .await
                .map_err(|e| io::Error::other(format!("tuic datagram: {e}")))?;
            return Ok(());
        }
        let total = u8::try_from(data.len().div_ceil(mtu)).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "tuic udp: > 255 фрагментов")
        })?;
        for (idx, chunk) in data.chunks(mtu).enumerate() {
            let Ok(fid) = u8::try_from(idx) else { break };
            let pkt = self.pack_frag(pid, fid, total, target, chunk)?;
            self.conn
                .send_datagram_wait(pkt.into())
                .await
                .map_err(|e| io::Error::other(format!("tuic datagram: {e}")))?;
        }
        Ok(())
    }

    /// Собрать один datagram CommandPacket (возможно фрагмент).
    pub fn pack_frag(
        &mut self,
        packet_id: u16,
        frag_id: u8,
        frag_total: u8,
        target: &TargetAddr,
        data: &[u8],
    ) -> io::Result<Vec<u8>> {
        let mut out = Vec::with_capacity(10 + 18 + data.len());
        out.push(5); // version
        out.push(2); // CommandPacket
        out.extend_from_slice(&self.session_id.to_be_bytes());
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

    /// Принять datagram, распаковать; фрагменты собираются по packetID.
    pub(crate) async fn recv(&mut self) -> io::Result<Vec<u8>> {
        loop {
            let dgram = self.conn.read_datagram().await.map_err(|e| {
                io::Error::new(io::ErrorKind::UnexpectedEof, format!("tuic recv: {e}"))
            })?;
            if let Some(data) = self.unpack(&dgram)? {
                return Ok(data);
            }
        }
    }

    fn unpack(&mut self, dgram: &[u8]) -> io::Result<Option<Vec<u8>>> {
        if dgram.len() < 10 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "tuic udp: короткий",
            ));
        }
        let pid = u16::from_be_bytes([dgram[2], dgram[3]]);
        let frag_total = dgram[4];
        let frag_id = dgram[5];
        // Заголовок: [ver][cmd][session u16][packet u16][fragTotal][fragID]
        // [dataLen u16] → данные после байта 10.
        let dlen = u16::from_be_bytes([dgram[8], dgram[9]]) as usize;
        let mut off = 10;
        // AddrPort (адрес перед портом — AddressSerializer без portFirst)
        let addr_len = addr_port_len(&dgram[off..])?;
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
        let parts = self.frags.entry(pid).or_default();
        parts.push((frag_id, data));
        if parts.len() == usize::from(frag_total) {
            parts.sort_by_key(|(id, _)| *id);
            let full: Vec<u8> = parts.iter().flat_map(|(_, d)| d.iter().copied()).collect();
            self.frags.remove(&pid);
            Ok(Some(full))
        } else {
            Ok(None)
        }
    }
}

/// Длина ATYP-адреса (tuic: адрес ПЕРЕД портом): atyp + адрес + port u16.
fn addr_port_len(b: &[u8]) -> io::Result<usize> {
    let Some(&atyp) = b.first() else {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "tuic addr: eof"));
    };
    match atyp {
        0x00 => Ok(usize::from(b.get(1).copied().unwrap_or(255)) + 4),
        0x01 => Ok(7),
        0x02 => Ok(19),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "tuic addr: ATYP",
        )),
    }
}

/// Длина ATYP-адреса цели (для расчёта MTU).
fn addr_port_len_of(target: &TargetAddr) -> io::Result<usize> {
    let mut probe = Vec::new();
    crate::tuic::write_addr_port(&mut probe, target);
    addr_port_len(&probe)
}

/// Свободная распаковка tuic CommandPacket datagram (для бенчей и recv).
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
    let addr_len = addr_port_len(&dgram[off..])?;
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

/// Свободная сборка CommandPacket (для бенчей; без соединения).
#[must_use]
pub fn pack_tuic_msg(
    session_id: u16,
    packet_id: u16,
    frag_total: u8,
    frag_id: u8,
    target: &TargetAddr,
    data: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(10 + 18 + data.len());
    out.push(5);
    out.push(2);
    out.extend_from_slice(&session_id.to_be_bytes());
    out.extend_from_slice(&packet_id.to_be_bytes());
    out.push(frag_total);
    out.push(frag_id);
    let dlen = u16::try_from(data.len()).unwrap_or(0xFFFF);
    out.extend_from_slice(&dlen.to_be_bytes());
    crate::tuic::write_addr_port(&mut out, target);
    out.extend_from_slice(data);
    out
}
