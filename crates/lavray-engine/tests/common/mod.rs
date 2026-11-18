// SPDX-License-Identifier: GPL-3.0-only

//! Общие e2e-хелперы: эхо-цель и mixed-прокси на ephemeral-портах.

use lavray_engine::{MixedConfig, MixedServer, start};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Эхо-сервер: отвечает байт-инверсией каждой порции.
pub async fn echo_server() -> std::io::Result<std::net::SocketAddr> {
    let ln = TcpListener::bind("127.0.0.1:0").await?;
    let addr = ln.local_addr()?;
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = ln.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                loop {
                    match s.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            for b in &mut buf[..n] {
                                *b = !*b;
                            }
                            if s.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    Ok(addr)
}

/// Поднимает mixed на :0; возвращает (прокси-адрес, сервер).
/// Не каждым тест-файлом используется (только engine_e2e).
#[allow(dead_code)]
pub async fn proxy() -> (std::net::SocketAddr, MixedServer) {
    let srv = start(MixedConfig {
        listen: "127.0.0.1:0".into(),
        socks_auth: None,
        ..Default::default()
    })
    .await
    .expect("mixed start");
    (srv.local_addr(), srv)
}

/// SOCKS5-рукопожатие клиента: no-auth + CONNECT на адрес эха + проверка REP=0.
/// Используется только ss_e2e (не всеми тест-файлами).
#[allow(dead_code)]
pub async fn socks_connect(c: &mut TcpStream, target: std::net::SocketAddr) -> std::io::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    c.write_all(&[0x05, 1, 0x00]).await?;
    let mut m = [0u8; 2];
    c.read_exact(&mut m).await?;
    assert_eq!(m, [0x05, 0x00]);
    let ip = match target.ip() {
        std::net::IpAddr::V4(v) => v.octets().to_vec(),
        std::net::IpAddr::V6(_) => unreachable!("эхо — loopback IPv4"),
    };
    let mut req = vec![0x05, 0x01, 0x00, 0x01];
    req.extend_from_slice(&ip);
    req.extend_from_slice(&target.port().to_be_bytes());
    c.write_all(&req).await?;
    let mut rep = [0u8; 10];
    c.read_exact(&mut rep).await?;
    assert_eq!(&rep[..2], &[0x05, 0x00], "REP: {rep:02x?}");
    Ok(())
}
