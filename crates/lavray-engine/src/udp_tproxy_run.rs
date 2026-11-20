// SPDX-License-Identifier: GPL-3.0-only

//! Цикл UDP tproxy: читающий поток (recvmsg → NAT) + TTL-чистка.
//! Конфиг/NAT-логика — `udp_tproxy`.

use crate::udp_tproxy::{Nat, UdpTproxyConfig, UdpTproxyError, nat_get_or_create, transparent_udp};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

/// Запустить UDP tproxy: читающий поток (recvmsg c orig-dst) → NAT →
/// upstream; ответы → клиент от имени цели; TTL-чистка записей.
///
/// # Errors
/// Сокет/бинд/потоки.
pub async fn run(
    cfg: UdpTproxyConfig,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<(), UdpTproxyError> {
    let std_sock = transparent_udp(&cfg.listen)
        .map_err(|e| UdpTproxyError(format!("udp listen {}: {e}", cfg.listen)))?;
    std_sock.set_nonblocking(true)?;
    let read_sock = std_sock
        .try_clone()
        .map_err(|e| UdpTproxyError(e.to_string()))?;
    let listener = Arc::new(
        tokio::net::UdpSocket::from_std(std_sock)
            .map_err(|e| UdpTproxyError(format!("async listener: {e}")))?,
    );
    let nat: Nat = Arc::new(Mutex::new(HashMap::new()));

    // Читающий поток: recvmsg → (client, orig_dst, data) → async-канал.
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<(SocketAddr, SocketAddr, Vec<u8>)>();
    std::thread::spawn(move || {
        use std::os::fd::AsRawFd as _;
        let mut buf = vec![0u8; 65_535];
        while let Ok((n, client, orig_dst)) =
            lavray_sys::recvmsg_orig_dst(read_sock.as_raw_fd(), &mut buf)
        {
            if tx.send((client, orig_dst, buf[..n].to_vec())).is_err() {
                break;
            }
        }
    });

    // TTL-чистка.
    let ttl = cfg.nat_ttl;
    let nat_clean = Arc::clone(&nat);
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(15));
        loop {
            tick.tick().await;
            let now = Instant::now();
            nat_clean
                .lock()
                .await
                .retain(|_, e| now.duration_since(e.last) < ttl);
        }
    });

    loop {
        tokio::select! {
            _ = shutdown.changed() => return Ok(()),
            msg = rx.recv() => {
                let Some((client, orig_dst, data)) = msg else {
                    break;
                };
                let sock =
                    nat_get_or_create(&nat, client, orig_dst, Arc::clone(&listener), true)
                        .await?;
                let _ = sock.send_to(&data, orig_dst).await;
            }
        }
    }
    Ok(())
}
