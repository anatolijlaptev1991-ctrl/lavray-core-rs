// SPDX-License-Identifier: GPL-3.0-only

//! Живой e2e TLS 1.3 (REALITY-стек): полный ручной handshake с реальным
//! сервером + HTTP GET через RealityStream. Запуск: cargo test -p
//! lavray-engine --test reality_live -- --ignored.

use lavray_engine::reality::{RealityConfig, handshake};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

fn cfg_for(sni: &str) -> RealityConfig {
    RealityConfig {
        sni: sni.to_string(),
        public_key: [1u8; 32], // не REALITY-сервер: shared будет низкокачественный, но handshake валиден
        short_id: [0u8; 8],
    }
}

#[tokio::test]
#[ignore = "live network"]
async fn manual_tls13_google_http_get() {
    let cfg = cfg_for("www.google.com");
    let tcp = TcpStream::connect(("www.google.com", 443))
        .await
        .expect("tcp connect");
    let hs = handshake(tcp, &cfg)
        .await
        .expect("manual TLS 1.3 handshake");
    // leaf не ed25519 → REALITY не подтверждён (это ожидаемо для обычного сайта)
    assert!(!hs.verified, "не-REALITY сервер не может быть verified");
    let mut stream = hs.stream;
    let request = format!(
        "GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n",
        host = cfg.sni
    );
    stream.write_all(request.as_bytes()).await.expect("write");
    stream.flush().await.expect("flush");
    let mut response = Vec::new();
    let deadline = Duration::from_secs(10);
    let _ = tokio::time::timeout(deadline, async {
        let mut chunk = [0u8; 8192];
        loop {
            match stream.read(&mut chunk).await {
                Ok(0) => {
                    eprintln!("dbg read: EOF");
                    break;
                }
                Err(e) => {
                    eprintln!("dbg read err: {e}");
                    break;
                }
                Ok(n) => response.extend_from_slice(&chunk[..n]),
            }
        }
    })
    .await;
    let text = String::from_utf8_lossy(&response);
    assert!(
        text.contains("HTTP/1.1 200") || text.contains("HTTP/1.1 30"),
        "должен быть HTTP-ответ, получено: {} байт, начало: {:?}",
        response.len(),
        &text[..text.len().min(120)]
    );
}

#[tokio::test]
#[ignore = "openssl s_server debug"]
async fn manual_tls13_openssl_local() {
    let cfg = cfg_for("localhost");
    let tcp = TcpStream::connect(("127.0.0.1", 4433)).await.expect("tcp");
    let hs = handshake(tcp, &cfg).await.expect("handshake");
    println!("handshake OK, verified={}", hs.verified);
    assert!(!hs.verified, "localhost RSA cert — не REALITY");
    // app-фаза: HTTP GET через RealityStream
    let mut stream = hs.stream;
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .expect("write");
    let mut response = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), async {
        let mut chunk = [0u8; 4096];
        loop {
            match stream.read(&mut chunk).await {
                Ok(0) => {
                    eprintln!("dbg read: EOF");
                    break;
                }
                Err(e) => {
                    eprintln!("dbg read err: {e}");
                    break;
                }
                Ok(n) => response.extend_from_slice(&chunk[..n]),
            }
        }
    })
    .await;
    let text = String::from_utf8_lossy(&response);
    println!(
        "response: {} bytes, head: {:?}",
        response.len(),
        &text[..text.len().min(60)]
    );
    assert!(
        text.contains("HTTP/1.1 200") || text.contains("HTTP/1.0 200"),
        "ожидался HTTP-ответ через шифрованный канал"
    );
}
