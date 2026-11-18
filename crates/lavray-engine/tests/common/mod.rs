// SPDX-License-Identifier: GPL-3.0-only

//! Общие e2e-хелперы: эхо-цель и mixed-прокси на ephemeral-портах.

use lavray_engine::{MixedConfig, MixedServer, start};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

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
