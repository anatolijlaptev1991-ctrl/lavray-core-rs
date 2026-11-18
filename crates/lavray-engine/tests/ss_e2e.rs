// SPDX-License-Identifier: GPL-3.0-only

//! E2E волны 7b: полный путь клиента LAVRay — SOCKS5 → mixed → SS-туннель
//! (AEAD-2022) → тестовый SS-сервер → эхо-цель. Всё loopback; проверяются
//! оба направления, мультичанковость (>16 КиБ) и все шесть AEAD-методов.

mod common;

use common::{echo_server, socks_connect};
use lavray_engine::ss::aead::Method;
use lavray_engine::ss::server as ss_test;
use lavray_engine::{MixedConfig, Outbound, TargetAddr, start};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

fn mixed_cfg(ss_addr: std::net::SocketAddr, method: Method, password: &str) -> MixedConfig {
    MixedConfig {
        listen: "127.0.0.1:0".into(),
        socks_auth: None,
        outbound: Outbound::Shadowsocks(Box::new(lavray_engine::ss::SsOutbound {
            server: TargetAddr::Ip(ss_addr.ip(), ss_addr.port()),
            method,
            password: password.into(),
        })),
    }
}

async fn ss_roundtrip(method: Method) {
    let echo = echo_server().await.unwrap();
    let ss = ss_test::start(method, "e2e-pass").await.unwrap();
    let srv = start(mixed_cfg(ss.addr, method, "e2e-pass")).await.unwrap();
    let mut c = TcpStream::connect(srv.local_addr()).await.unwrap();

    socks_connect(&mut c, echo).await.unwrap();

    // Малый обмен (один чанк).
    c.write_all(b"hello-ss").await.unwrap();
    let mut back = [0u8; 8];
    c.read_exact(&mut back).await.unwrap();
    let want: Vec<u8> = b"hello-ss".iter().map(|b| !*b).collect();
    assert_eq!(&back, want.as_slice(), "метод {method:?}");

    // Мультичанк: 3×16 КиБ + хвост через обе стороны.
    let big: Vec<u8> = (0..0xC000usize)
        .map(|i| u8::try_from(i % 251).expect("<251"))
        .collect();
    c.write_all(&big).await.unwrap();
    let mut got = vec![0u8; big.len()];
    c.read_exact(&mut got).await.unwrap();
    let inverted: Vec<u8> = big.iter().map(|b| !*b).collect();
    assert_eq!(got, inverted, "мультичанк {method:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn ss_2022_blake3_aes256_roundtrip() {
    ss_roundtrip(Method::Blake3Aes256).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn ss_2022_blake3_aes128_roundtrip() {
    ss_roundtrip(Method::Blake3Aes128).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn ss_2022_blake3_chacha20_roundtrip() {
    ss_roundtrip(Method::Blake3Chacha20).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn ss_legacy_aes128_roundtrip() {
    ss_roundtrip(Method::Aes128Gcm).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn ss_legacy_aes256_roundtrip() {
    ss_roundtrip(Method::Aes256Gcm).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn ss_legacy_chacha20_roundtrip() {
    ss_roundtrip(Method::Chacha20).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn ss_wrong_password_fails_stream() {
    let echo = echo_server().await.unwrap();
    let ss = ss_test::start(Method::Blake3Aes256, "right").await.unwrap();
    let srv = start(mixed_cfg(ss.addr, Method::Blake3Aes256, "wrong"))
        .await
        .unwrap();
    let mut c = TcpStream::connect(srv.local_addr()).await.unwrap();
    socks_connect(&mut c, echo).await.unwrap();
    c.write_all(b"x").await.unwrap();
    // Тег не сойдётся: сервер порвёт соединение — чтение даст 0/ошибку.
    let mut buf = [0u8; 4];
    let r = tokio::time::timeout(std::time::Duration::from_secs(3), c.read(&mut buf)).await;
    let n = r.expect("без вечного ожидания").unwrap();
    assert_eq!(
        n, 0,
        "сервер закрывает при неверном пароле, а не отдаёт мусор"
    );
}
