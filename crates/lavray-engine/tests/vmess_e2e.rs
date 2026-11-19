// SPDX-License-Identifier: GPL-3.0-only

//! E2E волны 7c (vmess): SOCKS5 → mixed → vmess-AEAD → тестовый сервер →
//! эхо. Оба шифра тела, мультичанк, доменные цели (резолв системный).

mod common;

use common::{echo_server, socks_connect};
use lavray_engine::vmess::server as vmess_test;
use lavray_engine::vmess::{Security, VmessOutbound};
use lavray_engine::{MixedConfig, Outbound, TargetAddr, start};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

fn mixed_cfg(vm_addr: std::net::SocketAddr, security: Security) -> MixedConfig {
    MixedConfig {
        listen: "127.0.0.1:0".into(),
        socks_auth: None,
        outbound: Outbound::Vmess(Box::new(VmessOutbound {
            server: TargetAddr::Ip(vm_addr.ip(), vm_addr.port()),
            uuid: UUID.into(),
            security,
        })),
    }
}

async fn vmess_roundtrip(security: Security) {
    let echo = echo_server().await.unwrap();
    let vm = vmess_test::start(UUID, security).await.unwrap();
    let srv = start(mixed_cfg(vm.addr, security)).await.unwrap();
    let mut c = TcpStream::connect(srv.local_addr()).await.unwrap();
    socks_connect(&mut c, echo).await.unwrap();
    c.write_all(b"hello-vmess").await.unwrap();
    let mut back = [0u8; 11];
    c.read_exact(&mut back).await.unwrap();
    let want: Vec<u8> = b"hello-vmess".iter().map(|b| !*b).collect();
    assert_eq!(&back, want.as_slice(), "security {security:?}");

    // Мультичанк (несколько блоков по 15000+тег).
    let big: Vec<u8> = (0..0x8000usize)
        .map(|i| u8::try_from(i % 251).expect("<251"))
        .collect();
    c.write_all(&big).await.unwrap();
    let mut got = vec![0u8; big.len()];
    c.read_exact(&mut got).await.unwrap();
    let inverted: Vec<u8> = big.iter().map(|b| !*b).collect();
    assert_eq!(got, inverted, "мультичанк {security:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn vmess_aes128gcm_roundtrip() {
    vmess_roundtrip(Security::Aes128Gcm).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn vmess_chacha20_roundtrip() {
    vmess_roundtrip(Security::Chacha20Poly1305).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn vmess_domain_target_resolves() {
    // Цель по домену 127.0.0.1 (loopback-резолв): проверяет PortThenAddress
    // FQDN-ветку заголовка.
    let echo = echo_server().await.unwrap();
    let vm = vmess_test::start(UUID, Security::Aes128Gcm).await.unwrap();
    // Прямой клиент (без mixed) с доменной целью.
    let (r, w) = lavray_engine::vmess::client::connect(
        &VmessOutbound {
            server: TargetAddr::Ip(vm.addr.ip(), vm.addr.port()),
            uuid: UUID.into(),
            security: Security::Aes128Gcm,
        },
        &TargetAddr::Domain("localhost".into(), echo.port()),
    )
    .await
    .unwrap();
    let (mut r, mut w) = (r, w);
    w.write_all(b"dom").await.unwrap();
    let mut back = [0u8; 3];
    let n = r.read(&mut back).await.unwrap();
    assert_eq!(n, 3);
    assert_eq!(back, [!b'd', !b'o', !b'm']);
}
