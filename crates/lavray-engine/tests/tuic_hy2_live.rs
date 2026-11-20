// SPDX-License-Identifier: GPL-3.0-only

//! Живые e2e тесты tuic/hysteria2 клиентов против реальных Go-серверов
//! (sing-box etalon 1.14.1-neko.1, конфиги etalon/live/*.json, порты
//! UDP 18443/18445, self-signed cert → skip_verify).
//! Схема: Rust-клиент → Go-сервер (direct outbound) → локальный TCP-echo.
//! Запуск: cargo test -p lavray-engine --test tuic_hy2_live -- --ignored --test-threads=1

use lavray_engine::addr::TargetAddr;
use lavray_engine::hy2::Hy2Config;
use lavray_engine::hy2_conn::connect_with_payload as hy2_connect;
use lavray_engine::tuic::{TuicConfig, connect as tuic_connect};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;

/// Локальный TCP-echo на эфемерном порту (цель через direct outbound Go).
async fn echo_server() -> (u16, tokio::task::JoinHandle<()>) {
    let lst = TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
    let port = lst.local_addr().expect("addr").port();
    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = lst.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if sock.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    (port, handle)
}

/// Сквозной прогон: подключиться прокси-клиентом к echo и получить свои байты.
async fn roundtrip<S: AsyncRead + AsyncWrite + Unpin>(
    connect: impl AsyncFnOnce() -> Result<S, String>,
    payload: &[u8],
) -> Result<(), String> {
    let mut s = connect().await?;
    s.write_all(payload).await.map_err(|e| e.to_string())?;
    s.flush().await.map_err(|e| e.to_string())?;
    let mut got = vec![0u8; 256];
    let n = s.read(&mut got).await.map_err(|e| format!("read: {e}"))?;
    assert_eq!(&got[..n], payload, "echo mismatch");
    Ok(())
}

#[tokio::test]
#[ignore = "live server (etalon/live, UDP 18443)"]
async fn tuic_live_echo() {
    let (echo_port, echo) = echo_server().await;
    let cfg = TuicConfig {
        server: "127.0.0.1".into(),
        server_port: 18443,
        sni: "127.0.0.1".into(),
        uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
        password: "testpw".into(),
        skip_verify: true, // self-signed cert сервера
    };
    roundtrip(
        async || {
            let server = "127.0.0.1:18443"
                .parse()
                .map_err(|e| format!("addr: {e}"))?;
            let target = TargetAddr::Ip(
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                echo_port,
            );
            tuic_connect(&cfg, &target, server)
                .await
                .map_err(|e| e.to_string())
        },
        b"tuic-live-e2e-hello",
    )
    .await
    .expect("tuic live echo");
    echo.abort();
}

#[tokio::test]
#[ignore = "live server (etalon/live, UDP 18445)"]
async fn hy2_live_echo() {
    let (echo_port, echo) = echo_server().await;
    // Порт сервера можно переопределить для реплики-отладчика (HY2_PORT).
    let port = std::env::var("HY2_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(18445);
    let cfg = Hy2Config {
        server: "127.0.0.1".into(),
        server_port: port,
        sni: "127.0.0.1".into(),
        password: "testpw".into(),
        rx_bps: 0,
        skip_verify: true,
    };
    let payload = b"hy2-live-e2e-hello";
    // parity Go clientConn: payload уходит вместе с TCPRequest
    let stream = hy2_connect(&cfg, "127.0.0.1", echo_port, payload)
        .await
        .expect("hy2 connect");
    roundtrip_read(stream, payload)
        .await
        .expect("hy2 live echo");
    echo.abort();
}

/// Читает эхо-ответ после того, как payload уже отправлен при connect.
async fn roundtrip_read<S: AsyncRead + Unpin>(mut s: S, payload: &[u8]) -> Result<(), String> {
    let mut got = vec![0u8; 256];
    let n = s.read(&mut got).await.map_err(|e| format!("read: {e}"))?;
    assert_eq!(&got[..n], payload, "echo mismatch");
    Ok(())
}
