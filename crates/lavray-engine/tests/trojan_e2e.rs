// SPDX-License-Identifier: GPL-3.0-only

//! E2E волны 7c (trojan): SOCKS5 → mixed → trojan/rustls → тестовый
//! trojan-сервер (rcgen self-signed) → эхо. Проверка hex(SHA224)-пароля,
//! релея внутри TLS и неверного пароля.

mod common;

use common::{echo_server, socks_connect};
use lavray_engine::trojan::TrojanOutbound;
use lavray_engine::trojan::server as trojan_test;
use lavray_engine::{MixedConfig, Outbound, TargetAddr, start};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

fn mixed_cfg(tj_addr: std::net::SocketAddr, password: &str) -> MixedConfig {
    MixedConfig {
        listen: "127.0.0.1:0".into(),
        socks_auth: None,
        outbound: Outbound::Trojan(Box::new(TrojanOutbound {
            server: TargetAddr::Ip(tj_addr.ip(), tj_addr.port()),
            password: password.into(),
            sni: "localhost".into(),
            skip_verify: true,
        })),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn trojan_roundtrip_echo() {
    let echo = echo_server().await.unwrap();
    let tj = trojan_test::start("e2e-pass").await.unwrap();
    let srv = start(mixed_cfg(tj.addr, "e2e-pass")).await.unwrap();
    let mut c = TcpStream::connect(srv.local_addr()).await.unwrap();
    socks_connect(&mut c, echo).await.unwrap();

    c.write_all(b"hello-trojan").await.unwrap();
    let mut back = [0u8; 12];
    c.read_exact(&mut back).await.unwrap();
    let want: Vec<u8> = b"hello-trojan".iter().map(|b| !*b).collect();
    assert_eq!(&back, want.as_slice());

    // Мультичанк через TLS-туннель.
    let big: Vec<u8> = (0..0xA000usize)
        .map(|i| u8::try_from(i % 251).expect("<251"))
        .collect();
    c.write_all(&big).await.unwrap();
    let mut got = vec![0u8; big.len()];
    c.read_exact(&mut got).await.unwrap();
    let inverted: Vec<u8> = big.iter().map(|b| !*b).collect();
    assert_eq!(got, inverted);
}

#[tokio::test(flavor = "multi_thread")]
async fn trojan_wrong_password_rejected() {
    let echo = echo_server().await.unwrap();
    let tj = trojan_test::start("right").await.unwrap();
    let srv = start(mixed_cfg(tj.addr, "wrong")).await.unwrap();
    let mut c = TcpStream::connect(srv.local_addr()).await.unwrap();
    socks_connect(&mut c, echo).await.unwrap();
    c.write_all(b"x").await.unwrap();
    let mut buf = [0u8; 8];
    let r = tokio::time::timeout(std::time::Duration::from_secs(3), c.read(&mut buf)).await;
    let n = r.expect("без вечного ожидания").unwrap();
    assert_eq!(n, 0, "сервер рвёт соединение при неверном пароле");
}
