// SPDX-License-Identifier: GPL-3.0-only

//! Целевой релей тестового vless-сервера (вынесено из server.rs
//! трещоткой размеров): разбор запроса, loopback-цель, ответ [0][0].

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::addr::TargetAddr;
use crate::relay;

use super::server::tokio_util_split;

pub(super) async fn relay_target<S>(mut stream: S, uid: &[u8; 16]) -> std::io::Result<()>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin + Send + 'static,
{
    // [ver][uuid16][addons][cmd][addr]
    let mut head = [0u8; 18];
    stream.read_exact(&mut head).await?;
    if head[0] != 0 {
        return Err(std::io::Error::other("vless: версия запроса"));
    }
    if &head[1..17] != uid {
        return Err(std::io::Error::other("vless: uuid отвергнут"));
    }
    let addons = head[17] as usize;
    if addons > 0 {
        let mut skip = vec![0u8; addons];
        stream.read_exact(&mut skip).await?;
        return Err(std::io::Error::other(
            "vless-тест: addons/flow не поддерживается тест-сервером",
        ));
    }
    // Читаем cmd+порт+ATYP по мере разбора: сначала 3 байта.
    let mut pre = [0u8; 3];
    stream.read_exact(&mut pre).await?;
    if pre[0] != 1 {
        return Err(std::io::Error::other("vless: только TCP"));
    }
    let port = u16::from_be_bytes([pre[1], pre[2]]);
    let mut atyp = [0u8; 1];
    stream.read_exact(&mut atyp).await?;
    let target = match atyp[0] {
        0x01 => {
            let mut b = [0u8; 4];
            stream.read_exact(&mut b).await?;
            TargetAddr::Ip(std::net::IpAddr::V4(b.into()), port)
        }
        0x02 => {
            let mut l = [0u8; 1];
            stream.read_exact(&mut l).await?;
            let mut d = vec![0u8; l[0] as usize];
            stream.read_exact(&mut d).await?;
            let name =
                String::from_utf8(d).map_err(|_| std::io::Error::other("vless: fqdn utf8"))?;
            TargetAddr::Domain(name, port)
        }
        0x03 => {
            let mut b = [0u8; 16];
            stream.read_exact(&mut b).await?;
            TargetAddr::Ip(std::net::IpAddr::V6(b.into()), port)
        }
        other => return Err(std::io::Error::other(format!("vless: ATYP {other:#04x}"))),
    };

    // Домен резолвится, цель обязана быть loopback.
    let (host, port) = match &target {
        TargetAddr::Ip(ip, p) => {
            if !ip.is_loopback() {
                return Err(std::io::Error::other("vless-тест: только loopback"));
            }
            (ip.to_string(), *p)
        }
        TargetAddr::Domain(d, p) => (d.clone(), *p),
    };
    let dest = TcpStream::connect((host.as_str(), port)).await?;
    let peer = dest
        .peer_addr()
        .map_err(|_| std::io::Error::other("vless-тест: только loopback"))?;
    if !peer.ip().is_loopback() {
        return Err(std::io::Error::other("vless-тест: только loopback"));
    }

    // Ответ: [0][0], затем прозрачный релей.
    stream.write_all(&[0, 0]).await?;
    let (r, w) = tokio_util_split(stream);
    let (dr, dw) = dest.into_split();
    relay::pump(dr, dw, r, w, Vec::new()).await?;
    Ok(())
}
