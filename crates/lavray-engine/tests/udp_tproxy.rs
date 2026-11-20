// SPDX-License-Identifier: GPL-3.0-only

//! Живой тест UDP tproxy NAT (Linux, loopback, без привилегий).
#![cfg(target_os = "linux")]

use lavray_engine::udp_tproxy::{Nat, nat_get_or_create, upstream_socket};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Живой тест (Linux): NAT entry bind(orig_dst) — на loopback
/// работает без привилегий; данные ходят client ↔ entry.sock.
#[tokio::test]
async fn nat_entry_roundtrip() {
    // «цель»: listener на эфемерном порту
    let target = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("target");
    let taddr = target.local_addr().expect("taddr");

    // entry-сокет: bind orig_dst (loopback эфемерный)
    let orig_dst: SocketAddr = "127.0.0.1:0".parse().expect("parse");
    let sock = Arc::new(upstream_socket(&orig_dst, false).expect("upstream"));
    let eaddr = sock.local_addr().expect("eaddr");

    let nat: Nat = Arc::new(Mutex::new(HashMap::new()));
    let client: SocketAddr = "127.0.0.1:0".parse().expect("parse");
    let reply_sock = Arc::new(
        tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("reply"),
    );
    // NAT-запись через публичный путь (transparent=false — без привилегий)
    let _ = nat_get_or_create(&nat, client, eaddr, Arc::clone(&reply_sock), false)
        .await
        .expect("nat entry");

    // клиентские данные → цель
    let table = nat.lock().await;
    let e = table.get(&client).expect("entry");
    e.sock
        .send_to(b"nat-pkt", taddr)
        .await
        .expect("send to target");
    drop(table);

    let mut buf = [0u8; 128];
    let (n, _) = target.recv_from(&mut buf).await.expect("target recv");
    assert_eq!(&buf[..n], b"nat-pkt");

    // ответ цели → entry.sock → reply_sock (клиенту)
    let _ = target.send_to(b"nat-reply2", eaddr).await.expect("reply2");
    let (n, _) = sock.recv_from(&mut buf).await.expect("entry recv");
    assert_eq!(&buf[..n], b"nat-reply2");
}
