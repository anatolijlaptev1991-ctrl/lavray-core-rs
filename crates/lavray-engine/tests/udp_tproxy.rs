// SPDX-License-Identifier: GPL-3.0-only

//! Живой тест UDP tproxy NAT (Linux, loopback, hy2 outbound):
//! nat_get_or_create создаёт UDP-канал движка (hy2 к etalon-серверу)
//! и reply-сокет bind(orig_dst). Требует запущенного hy2-сервера
//! (etalon/live, UDP 18445) и прав CAP_NET_ADMIN для bind(orig_dst).

#![cfg(target_os = "linux")]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;

#[tokio::test]
#[ignore = "requires hy2 server (etalon/live) + CAP_NET_ADMIN"]
async fn nat_entry_roundtrip() {
    let hy2_json = r#"{"type":"hysteria2","name":"h","address":"127.0.0.1","port":18445,"detail":{"password":"testpw"}}"#;
    let p: lavray_model::profile::Profile = serde_json::from_str(hy2_json).expect("profile");
    let outbound = Arc::new(lavray_engine::tun_proxy::check_profile(&p).expect("check"));
    let nat: lavray_engine::udp_tproxy::Nat = Arc::new(Mutex::new(HashMap::new()));
    let client: SocketAddr = "127.0.0.1:0".parse().expect("parse");
    let orig_dst: SocketAddr = "127.0.0.1:443".parse().expect("parse");

    let (reply, to_up) =
        lavray_engine::udp_tproxy::nat_get_or_create(&nat, client, orig_dst, false, &outbound)
            .await
            .expect("nat entry");

    // клиентские данные → pipe
    to_up.send(b"nat-pkt".to_vec()).expect("to_up");
    let _ = reply; // reply bind(orig_dst): отправка клиенту — src = цель
    to_up.send(b"".to_vec()).expect("to_up close");
}
