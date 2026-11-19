// SPDX-License-Identifier: GPL-3.0-only

//! Живые e2e-тесты обмена (запуск вручную: cargo test -p lavray-dns -- --ignored).

use lavray_dns::message::{FLAG_RD, Message, Question, RecordType};
use lavray_dns::{exchange_doh, exchange_dot, exchange_udp};
use std::time::Duration;

fn query(name: &str) -> Message {
    Message {
        header: lavray_dns::Header {
            id: 0x4242,
            flags: FLAG_RD,
            qd_count: 1,
            ..Default::default()
        },
        questions: vec![Question {
            name: name.into(),
            qtype: RecordType::A,
            qclass: 1,
        }],
        answers: vec![],
    }
}

#[tokio::test]
#[ignore = "live network"]
async fn udp_cloudflare_a() {
    let resp = exchange_udp("1.1.1.1:53", &query("example.com"), Duration::from_secs(3))
        .await
        .expect("udp");
    assert_eq!(resp.header.id, 0x4242);
    assert!(!resp.answers.is_empty(), "A-ответ должен быть");
}

#[tokio::test]
#[ignore = "live network"]
async fn doh_google_a() {
    let resp = exchange_doh(
        "https://dns.google/dns-query",
        &query("example.com"),
        Duration::from_secs(5),
    )
    .await
    .expect("doh");
    assert!(!resp.answers.is_empty(), "A-ответ должен быть");
}

#[tokio::test]
#[ignore = "live network"]
async fn dot_quad9_a() {
    let resp = exchange_dot(
        "dns.quad9.net:853",
        &query("example.com"),
        Duration::from_secs(5),
    )
    .await
    .expect("dot");
    assert!(!resp.answers.is_empty(), "A-ответ должен быть");
}
