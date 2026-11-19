// SPDX-License-Identifier: GPL-3.0-only

//! VLESS-клиент (v0, порт sing-vmess vless): собственный шифр отсутствует
//! — туннель даёт TLS (или транспорт); запрос [ver=0][uuid16][addons_len=0]
//! [cmd=1 TCP][ПОРТ ПЕРЕД адресом PortThenAddress], ответ [ver=0][addons_len],
//! далее прозрачный релей. Flow/xtls-rprx-vision — отдельная работа (7d+).

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::addr::TargetAddr;
use crate::direct::Transport;
use crate::relay::{UpRead, UpWrite};
use crate::tls::{TlsDial, connect as tls_connect};
use crate::vmess::client::uuid_bytes;

/// Параметры исходящего VLESS-туннеля.
#[derive(Debug, Clone)]
pub struct VlessOutbound {
    /// Адрес сервера.
    pub server: TargetAddr,
    /// UUID пользователя.
    pub uuid: String,
    /// TLS (None — плоский TCP, только для тестов/локальных туннелей).
    pub tls: Option<TlsDial>,
    /// Транспорт (TCP по умолчанию; ws — волна 7e).
    pub transport: Transport,
}

/// Запрос VLESS: [0][uuid16][0][1][port BE][ATYP+addr] (+ payload следом).
#[must_use]
pub fn request_bytes(uuid: &[u8; 16], target: &TargetAddr) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 16 + 1 + 1 + 2 + 1 + 255);
    out.push(0); // version
    out.extend_from_slice(uuid);
    out.push(0); // addons length (без flow)
    out.push(1); // command TCP
    match target {
        TargetAddr::Domain(d, p) => {
            out.extend_from_slice(&p.to_be_bytes());
            out.push(0x02);
            out.push(u8::try_from(d.len()).unwrap_or(255));
            out.extend_from_slice(d.as_bytes());
        }
        TargetAddr::Ip(std::net::IpAddr::V4(v), p) => {
            out.extend_from_slice(&p.to_be_bytes());
            out.push(0x01);
            out.extend_from_slice(&v.octets());
        }
        TargetAddr::Ip(std::net::IpAddr::V6(v), p) => {
            out.extend_from_slice(&p.to_be_bytes());
            out.push(0x03);
            out.extend_from_slice(&v.octets());
        }
    }
    out
}

/// Установить туннель: TCP (+TLS) → запрос → чтение ответа [0][0] → половины.
pub async fn connect(o: &VlessOutbound, target: &TargetAddr) -> std::io::Result<(UpRead, UpWrite)> {
    let uid =
        uuid_bytes(&o.uuid).ok_or_else(|| std::io::Error::other("vless: некорректный UUID"))?;
    let tcp = TcpStream::connect((o.server.host_string().as_str(), o.server.port())).await?;
    let _ = tcp.set_nodelay(true);

    let request = request_bytes(&uid, target);
    match &o.transport {
        Transport::Tcp => match o.tls.as_ref() {
            None => {
                let mut stream = tcp;
                stream.write_all(&request).await?;
                read_response(&mut stream).await?;
                let (r, w) = stream.into_split();
                Ok((Box::pin(r), Box::pin(w)))
            }
            Some(dial) => {
                let mut tls = tls_connect(tcp, dial, &o.server.host_string()).await?;
                tls.write_all(&request).await?;
                read_response(&mut tls).await?;
                let (r, w) = tokio::io::split(tls);
                Ok((Box::pin(r), Box::pin(w)))
            }
        },
        Transport::Ws(dial_ws) => {
            // Upgrade поверх plain TCP → фреймы. ws+TLS — подволна 7e-2
            // (handshake над TlsStream требует generic-половин).
            if o.tls.is_some() {
                return Err(std::io::Error::other("vless: ws+TLS — волна 7e-2"));
            }
            let (mut r, mut w) =
                crate::ws::handshake(tcp, dial_ws, &o.server.host_string()).await?;
            w.write_all(&request).await?;
            read_response(&mut r).await?;
            Ok((Box::pin(r), Box::pin(w)))
        }
    }
}

/// Ответ сервера: [version][addons_len] ( addons пропускаются ).
async fn read_response<S>(s: &mut S) -> std::io::Result<()>
where
    S: AsyncReadExt + Unpin,
{
    let mut hdr = [0u8; 2];
    s.read_exact(&mut hdr).await?;
    if hdr[0] != 0 {
        return Err(std::io::Error::other(format!(
            "vless: версия ответа {}",
            hdr[0]
        )));
    }
    let mut addons = vec![0u8; hdr[1] as usize];
    if !addons.is_empty() {
        s.read_exact(&mut addons).await?;
    }
    Ok(())
}
