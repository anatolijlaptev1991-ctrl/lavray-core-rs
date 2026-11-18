// SPDX-License-Identifier: GPL-3.0-only

//! SOCKS5-инбаунд (RFC 1928/1929): методы 0x00 (no-auth) и 0x02
//! (username/password), команды CONNECT (BIND/UDP — отказ 0x07), адреса
//! IPv4/IPv6/домен. Свой парсер без зависимостей — hot-path движка;
//! generic по потоку (один и тот же сокет на чтение и запись).

use std::net::IpAddr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::addr::TargetAddr;

/// Ответ-код SOCKS5 (REP).
mod rep {
    pub const OK: u8 = 0x00;
    pub const GENERAL: u8 = 0x01;
    pub const NOT_ALLOWED: u8 = 0x02;
    pub const CMD: u8 = 0x07;
    pub const ADDR: u8 = 0x08;
}

const MAX_DOMAIN: usize = 255;

/// Прочитать handshake (VER NMETHODS METHODS…) и согласовать метод.
/// `auth` — логин/пароль для 0x02 (None — только no-auth).
pub async fn handshake<S>(s: &mut S, auth: Option<(&str, &str)>) -> std::io::Result<bool>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let mut hdr = [0u8; 2];
    s.read_exact(&mut hdr).await?;
    if hdr[0] != 0x05 {
        return Err(proto(format!("не SOCKS5 (VER={:#04x})", hdr[0])));
    }
    let n = hdr[1] as usize;
    if n == 0 || n > 255 {
        return Err(proto(format!("некорректное число методов {n}")));
    }
    let mut methods = vec![0u8; n]; // ≤255 байт — аллокация пренебрежима
    s.read_exact(&mut methods).await?;
    if methods.contains(&0x00) {
        s.write_all(&[0x05, 0x00]).await?;
        return Ok(false); // без авторизации
    }
    if let Some((user, pass)) = auth.filter(|_| methods.contains(&0x02)) {
        s.write_all(&[0x05, 0x02]).await?;
        return userpass(s, user, pass).await;
    }
    s.write_all(&[0x05, 0xFF]).await?; // нет приемлемых методов
    Err(proto(format!(
        "нет приемлемых методов (клиент предложил {methods:02x?})"
    )))
}

async fn userpass<S>(s: &mut S, user: &str, pass: &str) -> std::io::Result<bool>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    // RFC 1929: VER(0x01) ULEN UNAME PLEN PASSWD.
    let mut head = [0u8; 2];
    s.read_exact(&mut head).await?;
    if head[0] != 0x01 {
        return Err(proto(format!("userpass: VER={:#04x}", head[0])));
    }
    let mut uname = vec![0u8; head[1] as usize];
    s.read_exact(&mut uname).await?;
    let mut plen = [0u8; 1];
    s.read_exact(&mut plen).await?;
    let mut passwd = vec![0u8; plen[0] as usize];
    s.read_exact(&mut passwd).await?;
    let ok = uname == user.as_bytes() && passwd == pass.as_bytes();
    s.write_all(if ok { &[1, 0] } else { &[1, 1] }).await?;
    if ok {
        Ok(true)
    } else {
        Err(proto("userpass: неверные учётные данные".into()))
    }
}

/// Прочитать REQUEST; цель CONNECT (`None` — команда не CONNECT, отказ уже
/// отправлен). Данные после заголовка запроса клиент шлёт только после
/// нашего reply — парсер их не касается.
pub async fn read_request<S>(s: &mut S) -> std::io::Result<Option<TargetAddr>>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let mut head = [0u8; 4]; // VER CMD RSV ATYP
    s.read_exact(&mut head).await?;
    if head[0] != 0x05 {
        return Err(proto(format!("REQUEST: VER={:#04x}", head[0])));
    }
    let addr = match parse_atyp(s, head[3]).await {
        Ok(a) => a,
        Err(e) => {
            let _ = reply(s, rep::ADDR).await;
            return Err(e);
        }
    };
    if head[1] != 0x01 {
        // Только CONNECT; BIND(0x02)/UDP(0x03) — отказ CMD not supported.
        let _ = reply(s, rep::CMD).await;
        return Ok(None);
    }
    Ok(Some(addr))
}

async fn parse_atyp<S>(s: &mut S, atyp: u8) -> std::io::Result<TargetAddr>
where
    S: AsyncReadExt + Unpin,
{
    let mut port = [0u8; 2];
    match atyp {
        0x01 => {
            let mut b = [0u8; 4];
            s.read_exact(&mut b).await?;
            s.read_exact(&mut port).await?;
            Ok(TargetAddr::Ip(
                IpAddr::V4(b.into()),
                u16::from_be_bytes(port),
            ))
        }
        0x03 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l).await?;
            if l[0] as usize > MAX_DOMAIN {
                return Err(proto(format!("домен длиннее {MAX_DOMAIN}")));
            }
            let mut d = vec![0u8; l[0] as usize];
            s.read_exact(&mut d).await?;
            s.read_exact(&mut port).await?;
            let name = String::from_utf8(d).map_err(|_| proto("домен не UTF-8".into()))?;
            Ok(TargetAddr::Domain(name, u16::from_be_bytes(port)))
        }
        0x04 => {
            let mut b = [0u8; 16];
            s.read_exact(&mut b).await?;
            s.read_exact(&mut port).await?;
            Ok(TargetAddr::Ip(
                IpAddr::V6(b.into()),
                u16::from_be_bytes(port),
            ))
        }
        other => Err(proto(format!("ATYP={other:#04x}"))),
    }
}

/// Ответ на REQUEST (BND = 0.0.0.0:0 — прокси не публикует свой адрес).
pub async fn reply<S>(s: &mut S, code: u8) -> std::io::Result<()>
where
    S: AsyncWriteExt + Unpin,
{
    s.write_all(&[0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await
}

/// Успех-шорткат.
pub async fn reply_ok<S>(s: &mut S) -> std::io::Result<()>
where
    S: AsyncWriteExt + Unpin,
{
    reply(s, rep::OK).await
}

/// Отказ цели (upstream connect не удался).
pub async fn reply_fail<S>(s: &mut S) -> std::io::Result<()>
where
    S: AsyncWriteExt + Unpin,
{
    reply(s, rep::GENERAL).await
}

/// Запрещено политикой.
pub async fn reply_denied<S>(s: &mut S) -> std::io::Result<()>
where
    S: AsyncWriteExt + Unpin,
{
    reply(s, rep::NOT_ALLOWED).await
}

fn proto(msg: String) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, msg)
}
