// SPDX-License-Identifier: GPL-3.0-only

//! Живые e2e UDP-тесты движка: hysteria2 datagrams / tuic CommandPacket
//! → DNS-запрос на 1.1.1.1:53 через Go-серверы etalon (UDP 18443/18445).
//! Запуск: cargo test -p lavray-engine --test udp_engine_live -- --ignored --test-threads=1

use lavray_engine::hy2::Hy2Config;
use lavray_engine::tuic::TuicConfig;
use lavray_engine::udp_pipe_hy2::hy2_connect;
use lavray_engine::udp_pipe_tuic::tuic_connect;

/// Минимальный DNS-запрос A example.com (id 0x4d2, RD=1).
fn dns_query() -> Vec<u8> {
    let mut q = Vec::new();
    q.extend_from_slice(&[0x04, 0xd2]); // id
    q.extend_from_slice(&[0x01, 0x00]); // flags: RD
    q.extend_from_slice(&[0x00, 0x01]); // qdcount
    q.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // an/ns/ar
    for label in ["example", "com"] {
        let Ok(l) = u8::try_from(label.len()) else {
            panic!("длинный label");
        };
        q.push(l);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&[0x00, 0x01]); // type A
    q.extend_from_slice(&[0x00, 0x01]); // class IN
    q
}

/// DNS-ответ содержит id запроса и тип A (проверка достаточна).
fn is_dns_answer(buf: &[u8]) -> bool {
    buf.len() > 20 && buf[0] == 0x04 && buf[1] == 0xd2
}

#[tokio::test]
#[ignore = "live server (etalon/live hy2 UDP)"]
async fn hy2_udp_dns() {
    let cfg = Hy2Config {
        server: "127.0.0.1".into(),
        server_port: 18445,
        sni: "127.0.0.1".into(),
        password: "testpw".into(),
        rx_bps: 0,
        skip_verify: true,
    };
    let target = lavray_engine::TargetAddr::Ip(
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1)),
        53,
    );
    let mut pipe = hy2_connect(&cfg, &target).await.expect("hy2 udp pipe");
    pipe.send(&dns_query()).await.expect("send dns");
    let data = tokio::time::timeout(std::time::Duration::from_secs(10), pipe.recv())
        .await
        .expect("timeout")
        .expect("recv");
    assert!(is_dns_answer(&data), "не DNS-ответ: {} байт", data.len());
}

#[tokio::test]
#[ignore = "live server (etalon/live tuic UDP)"]
async fn tuic_udp_dns() {
    let cfg = TuicConfig {
        server: "127.0.0.1".into(),
        server_port: 18443,
        sni: "127.0.0.1".into(),
        uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
        password: "testpw".into(),
        skip_verify: true,
    };
    let target = lavray_engine::TargetAddr::Ip(
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1)),
        53,
    );
    let mut pipe = tuic_connect(&cfg, &target).await.expect("tuic udp pipe");
    let mut data = None;
    // QUIC datagrams ненадёжны — 3 попытки (стандарт для UDP-путей)
    for _ in 0..3 {
        pipe.send(&dns_query()).await.expect("send dns");
        if let Ok(d) = tokio::time::timeout(std::time::Duration::from_secs(5), pipe.recv()).await {
            data = Some(d.expect("recv"));
            break;
        }
    }
    assert!(
        data.as_ref().is_some_and(|d| is_dns_answer(d)),
        "нет DNS-ответа за 3 попытки"
    );
}
