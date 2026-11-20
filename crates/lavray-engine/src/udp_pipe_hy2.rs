// SPDX-License-Identifier: GPL-3.0-only

//! Hysteria2 UDP-канал: QUIC datagrams udpMessage (sessionID/packetID/
//! фрагменты), паритет sing-quic hysteria2 packet.go. QUIC-сессия с auth
//! — connect_hy2_udp (ниже).

use crate::addr::TargetAddr;
use crate::hy2::Hy2Config;
use crate::hy2_config::Hy2Error;
use crate::udp_pipe::UdpPipe;
use std::collections::HashMap;
use std::io;
use std::sync::Arc;

/// Hysteria2 UDP-канал (QUIC datagrams; sessionID per канал).
pub struct Hy2Udp {
    conn: quinn::Connection,
    session_id: u32,
    packet_id: u16,
    /// Сборка фрагментов: (packet_id) → [(frag_id, data)].
    frags: HashMap<u16, Vec<(u8, Vec<u8>)>>,
    /// Hold uni-потоков (control/QPACK) — живут до конца сессии.
    pub(crate) _hold: Arc<[quinn::SendStream; 3]>,
}

/// Подключить hysteria2 UDP-канал (QUIC + H3-минимум + auth + datagrams).
///
/// # Errors
/// I/O / TLS / auth.
pub async fn hy2_connect(cfg: &Hy2Config, target: &TargetAddr) -> io::Result<UdpPipe> {
    let (conn, hold) = connect_hy2_udp(cfg).await.map_err(std::io::Error::other)?;
    let session_id = rand_u32();
    Ok(UdpPipe::Hy2(
        Hy2Udp {
            conn,
            session_id,
            packet_id: 0,
            frags: HashMap::new(),
            _hold: hold,
        },
        target.clone(),
    ))
}

/// QUIC-сессия с auth для UDP-каналов: соединение + hold uni-потоков
/// (control/QPACK живут до конца сессии).
///
/// # Errors
/// I/O / TLS / auth.
pub async fn connect_hy2_udp(
    cfg: &Hy2Config,
) -> Result<(quinn::Connection, Arc<[quinn::SendStream; 3]>), Hy2Error> {
    let client_cfg = crate::quic_tls::client_config(cfg.skip_verify, &["h3"])
        .map_err(|e| Hy2Error(e.clone()))?;
    let addr = crate::hy2_conn::resolve_server(&cfg.server, cfg.server_port).await?;
    let mut endpoint = quinn::Endpoint::client(
        "0.0.0.0:0"
            .parse()
            .map_err(|e| Hy2Error(format!("bind: {e}")))?,
    )
    .map_err(|e| Hy2Error(format!("endpoint: {e}")))?;
    endpoint.set_default_client_config(client_cfg);
    let conn = endpoint
        .connect(addr, &cfg.sni)
        .map_err(|e| Hy2Error(format!("connect: {e}")))?
        .await
        .map_err(|e| Hy2Error(format!("quic handshake: {e}")))?;
    let (control, qenc, qdec) = crate::hy2_conn::open_h3_streams(&conn).await?;
    crate::hy2_conn::auth(&conn, cfg).await?;
    Ok((conn, Arc::new([control, qenc, qdec])))
}

fn rand_u32() -> u32 {
    let mut b = [0u8; 4];
    let _ = getrandom::fill(&mut b);
    u32::from_ne_bytes(b)
}

pub(crate) fn rand_u16() -> u16 {
    let mut b = [0u8; 2];
    let _ = getrandom::fill(&mut b);
    u16::from_ne_bytes(b)
}

impl Hy2Udp {
    /// Адрес-строка цели «host:port» (parity M.Socksaddr.String()).
    fn dest_string(target: &TargetAddr) -> String {
        match target {
            TargetAddr::Domain(d, p) => format!("{d}:{p}"),
            TargetAddr::Ip(ip, p) => format!("{ip}:{p}"),
        }
    }

    /// Отправить пакет: ≤ MTU — один datagram, больше — фрагменты
    /// (parity Go fragUDPMessage: destination в КАЖДОМ фрагменте,
    /// fragmentTotal = число частей, fragmentID = индекс).
    pub(crate) async fn send(&mut self, data: &[u8], target: &TargetAddr) -> io::Result<()> {
        let dest = Self::dest_string(target);
        let mtu = crate::hy2_config::udp_mtu(&dest);
        if mtu == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "hy2 udp: dest слишком длинный",
            ));
        }
        self.packet_id = self.packet_id.wrapping_add(1);
        let pid = self.packet_id;
        if data.len() <= mtu {
            let pkt = Self::pack_frag(self.session_id, pid, 0, 1, &dest, data);
            self.conn
                .send_datagram_wait(pkt.into())
                .await
                .map_err(|e| io::Error::other(format!("hy2 datagram: {e}")))?;
            return Ok(());
        }
        let total = u8::try_from(data.len().div_ceil(mtu))
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "hy2 udp: > 255 фрагментов"))?;
        for (idx, chunk) in data.chunks(mtu).enumerate() {
            let Ok(fid) = u8::try_from(idx) else { break };
            let pkt = Self::pack_frag(self.session_id, pid, fid, total, &dest, chunk);
            self.conn
                .send_datagram_wait(pkt.into())
                .await
                .map_err(|e| io::Error::other(format!("hy2 datagram: {e}")))?;
        }
        Ok(())
    }

    /// Собрать один datagram udpMessage (возможно фрагмент).
    fn pack_frag(
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
        crate::hy2_config::write_varint(&mut out, dest.len() as u64);
        out.extend_from_slice(dest.as_bytes());
        out.extend_from_slice(data);
        out
    }

    /// Принять datagram, распаковать, собрать фрагменты; вернуть данные.
    pub(crate) async fn recv(&mut self) -> io::Result<Vec<u8>> {
        loop {
            let dgram = self.conn.read_datagram().await.map_err(|e| {
                io::Error::new(io::ErrorKind::UnexpectedEof, format!("hy2 recv: {e}"))
            })?;
            if let Some(data) = self.unpack(&dgram)? {
                return Ok(data);
            }
        }
    }

    fn unpack(&mut self, dgram: &[u8]) -> io::Result<Option<Vec<u8>>> {
        if dgram.len() < 8 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "hy2 udp: короткий",
            ));
        }
        let pid = u16::from_be_bytes([dgram[4], dgram[5]]);
        let frag_id = dgram[6];
        let frag_total = dgram[7];
        // VString destination
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
        // defrag
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
