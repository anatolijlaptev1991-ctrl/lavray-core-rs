// SPDX-License-Identifier: GPL-3.0-only

//! E2E волны 7d (vless): SOCKS5 → mixed → vless (plain и TLS) → тестовый
//! сервер → эхо. Мультичанк, доменная цель, чужой UUID — отказ.

mod common;

use common::{echo_server, socks_connect};
use lavray_engine::Transport;
use lavray_engine::tls::TlsDial;
use lavray_engine::vless::VlessOutbound;
use lavray_engine::vless::server as vless_test;
use lavray_engine::ws::WsDial;
use lavray_engine::{MixedConfig, Outbound, TargetAddr, start};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

fn mixed_cfg(vs_addr: std::net::SocketAddr, tls: Option<TlsDial>) -> MixedConfig {
    MixedConfig {
        listen: "127.0.0.1:0".into(),
        socks_auth: None,
        outbound: Outbound::Vless(Box::new(VlessOutbound {
            server: TargetAddr::Ip(vs_addr.ip(), vs_addr.port()),
            uuid: UUID.into(),
            tls,
            transport: Transport::default(),
        })),
    }
}

async fn vless_roundtrip(with_tls: bool) {
    let echo = echo_server().await.unwrap();
    let vs = if with_tls {
        vless_test::start_tls(UUID).await.unwrap()
    } else {
        vless_test::start(UUID).await.unwrap()
    };
    let tls = with_tls.then(|| TlsDial {
        sni: "localhost".into(),
        skip_verify: true,
    });
    let srv = start(mixed_cfg(vs.addr, tls)).await.unwrap();
    let mut c = TcpStream::connect(srv.local_addr()).await.unwrap();
    socks_connect(&mut c, echo).await.unwrap();

    c.write_all(b"hello-vless").await.unwrap();
    let mut back = [0u8; 11];
    c.read_exact(&mut back).await.unwrap();
    let want: Vec<u8> = b"hello-vless".iter().map(|b| !*b).collect();
    assert_eq!(&back, want.as_slice(), "tls={with_tls}");

    let big: Vec<u8> = (0..0x9000usize)
        .map(|i| u8::try_from(i % 251).expect("<251"))
        .collect();
    c.write_all(&big).await.unwrap();
    let mut got = vec![0u8; big.len()];
    c.read_exact(&mut got).await.unwrap();
    let inverted: Vec<u8> = big.iter().map(|b| !*b).collect();
    assert_eq!(got, inverted, "мультичанк tls={with_tls}");
}

#[tokio::test(flavor = "multi_thread")]
async fn vless_plain_roundtrip() {
    vless_roundtrip(false).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn vless_tls_roundtrip() {
    vless_roundtrip(true).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn vless_domain_target_resolves() {
    let echo = echo_server().await.unwrap();
    let vs = vless_test::start(UUID).await.unwrap();
    let (mut r, mut w) = lavray_engine::vless::client::connect(
        &VlessOutbound {
            server: TargetAddr::Ip(vs.addr.ip(), vs.addr.port()),
            uuid: UUID.into(),
            tls: None,
            transport: Transport::default(),
        },
        &TargetAddr::Domain("localhost".into(), echo.port()),
    )
    .await
    .unwrap();
    w.write_all(b"dom").await.unwrap();
    let mut back = [0u8; 3];
    let n = r.read(&mut back).await.unwrap();
    assert_eq!(n, 3);
    assert_eq!(back, [!b'd', !b'o', !b'm']);
}

#[tokio::test(flavor = "multi_thread")]
async fn vless_wrong_uuid_rejected() {
    let echo = echo_server().await.unwrap();
    let vs = vless_test::start(UUID).await.unwrap();
    let err = lavray_engine::vless::client::connect(
        &VlessOutbound {
            server: TargetAddr::Ip(vs.addr.ip(), vs.addr.port()),
            uuid: "00000000-0000-0000-0000-000000000000".into(),
            tls: None,
            transport: Transport::default(),
        },
        &TargetAddr::Ip(echo.ip(), echo.port()),
    )
    .await;
    // Ответ-заголовок [0][0] не придёт: сервер рвёт соединение после UUID.
    assert!(err.is_err(), "чужой UUID обязан отвергаться");
}

#[tokio::test(flavor = "multi_thread")]
async fn vless_over_ws_roundtrip() {
    let echo = echo_server().await.unwrap();
    let vs = vless_test::start_ws(UUID).await.unwrap();
    let srv = start(MixedConfig {
        listen: "127.0.0.1:0".into(),
        socks_auth: None,
        outbound: Outbound::Vless(Box::new(VlessOutbound {
            server: TargetAddr::Ip(vs.addr.ip(), vs.addr.port()),
            uuid: UUID.into(),
            tls: None,
            transport: lavray_engine::Transport::Ws(WsDial {
                path: "/ws".into(),
                host: String::new(),
            }),
        })),
    })
    .await
    .unwrap();
    let mut c = TcpStream::connect(srv.local_addr()).await.unwrap();
    socks_connect(&mut c, echo).await.unwrap();

    c.write_all(b"hello-vless-ws").await.unwrap();
    let mut back = [0u8; 14];
    c.read_exact(&mut back).await.unwrap();
    let want: Vec<u8> = b"hello-vless-ws".iter().map(|b| !*b).collect();
    assert_eq!(&back, want.as_slice());

    // Мультифрейм: несколько ws-фреймов через весь стек.
    let big: Vec<u8> = (0..0x8000usize)
        .map(|i| u8::try_from(i % 251).expect("<251"))
        .collect();
    c.write_all(&big).await.unwrap();
    let mut got = vec![0u8; big.len()];
    c.read_exact(&mut got).await.unwrap();
    let inverted: Vec<u8> = big.iter().map(|b| !*b).collect();
    assert_eq!(got, inverted);
}
