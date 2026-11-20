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
    fn pack(&mut self, data: &[u8], target: &TargetAddr) -> io::Result<Vec<u8>> {
        self.packet_id = self.packet_id.wrapping_add(1);
        let pid = self.packet_id;
        let mut out = Vec::with_capacity(10 + 18 + data.len());
        out.push(5); // version
        out.push(2); // CommandPacket (iota-блок: auth=0, connect=1, packet=2)
        out.extend_from_slice(&self.session_id.to_be_bytes());
        out.extend_from_slice(&pid.to_be_bytes());
        out.push(1); // fragmentTotal
        out.push(0); // fragmentID
        let dlen = u16::try_from(data.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "tuic udp: > 65535"))?;
        out.extend_from_slice(&dlen.to_be_bytes());
        crate::tuic::write_addr_port(&mut out, target);
        out.extend_from_slice(data);
        Ok(out)
    }

    pub(crate) async fn send(&mut self, data: &[u8], target: &TargetAddr) -> io::Result<()> {
        if data.len() > 1200 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "tuic udp: пакет > 1200 (фрагментация — волна QUIC-UDP-2)",
            ));
        }
        let pkt = self.pack(data, target)?;
        self.conn
            .send_datagram_wait(pkt.into())
            .await
            .map_err(|e| io::Error::other(format!("tuic datagram: {e}")))
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
