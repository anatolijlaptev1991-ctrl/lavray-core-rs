// SPDX-License-Identifier: GPL-3.0-only

//! Mixed-сервер (волна 7a): SOCKS5 и HTTP CONNECT на одном слушателе
//! (паритет sing-box «mixed»; детект по первому байту 0x05). Активные
//! соединения считаются; stop закрывает слушатель, релеи докачиваются.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{oneshot::Receiver, watch};

use crate::addr::TargetAddr;
use crate::direct::Outbound;
use crate::http_connect;
use crate::relay;
use crate::sniff::Sniffed;
use crate::socks5;

/// Конфигурация mixed-сервера.
#[derive(Debug, Clone, Default)]
pub struct MixedConfig {
    /// Адрес слушателя («127.0.0.1:2080»; порт 0 — ephemeral).
    pub listen: String,
    /// Логин/пароль SOCKS5 userpass (None — только no-auth).
    pub socks_auth: Option<(String, String)>,
    /// Исходящий канал всех соединений (7a: direct).
    pub outbound: Outbound,
}

/// Запущенный сервер.
pub struct MixedServer {
    local_addr: std::net::SocketAddr,
    stop: watch::Sender<bool>,
    done: Receiver<()>,
    active: Arc<AtomicUsize>,
}

impl MixedServer {
    /// Локальный адрес (порт мог быть :0).
    #[must_use]
    pub fn local_addr(&self) -> std::net::SocketAddr {
        self.local_addr
    }

    /// Число активных клиентских соединений.
    #[must_use]
    pub fn active(&self) -> usize {
        self.active.load(Ordering::Relaxed)
    }

    /// Попросить остановку (слушатель закрывается; релеи докачиваются).
    pub fn stop(&self) {
        let _ = self.stop.send(true);
    }

    /// Ждать фактического закрытия слушателя (задача accept-цикла уже
    /// вышла и дропнула listener): новые connect-ы гарантированно отказывают.
    pub async fn join(self) {
        let _ = self.done.await;
    }
}

/// Запустить mixed-сервер; возвращается немедленно.
pub async fn start(cfg: MixedConfig) -> std::io::Result<MixedServer> {
    let listener = TcpListener::bind(&cfg.listen).await?;
    let local_addr = listener.local_addr()?;
    let (stop_tx, stop_rx) = watch::channel(false);
    let active = Arc::new(AtomicUsize::new(0));

    let task_active = Arc::clone(&active);
    let outbound = cfg.outbound;
    let auth = cfg.socks_auth;
    let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();
    // Подписка синхронно ДО spawn: stop() раньше первой итерации всё равно
    // разбудит changed (select с if-precondition не будит спящий accept).
    let mut stop_rx_task = stop_rx.clone();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = stop_rx_task.changed() => {
                    if *stop_rx_task.borrow_and_update() {
                        break;
                    }
                }
                accepted = listener.accept() => {
                    let Ok((stream, _peer)) = accepted else { continue };
                    let outbound = outbound.clone();
                    let auth = auth.clone();
                    let active = Arc::clone(&task_active);
                    active.fetch_add(1, Ordering::Relaxed);
                    tokio::spawn(async move {
                        serve_conn(stream, auth.as_ref().map(|(u, p)| (u.as_str(), p.as_str())), outbound).await;
                        active.fetch_sub(1, Ordering::Relaxed);
                    });
                }
            }
        }
        // Выход из accept-цикла: слушатель дропнут — сообщаем join.
        let _ = done_tx.send(());
    });

    Ok(MixedServer {
        local_addr,
        stop: stop_tx,
        done: done_rx,
        active,
    })
}

/// Одно соединение: детект протокола → handshake → цель → outbound → relay.
async fn serve_conn(stream: TcpStream, auth: Option<(&str, &str)>, outbound: Outbound) {
    let mut stream = stream;
    let _ = stream.set_nodelay(true);
    let mut first = [0u8; 1];
    if stream.read_exact(&mut first).await.is_err() {
        return; // обрыв до первого байта
    }
    let result = if first[0] == 0x05 {
        socks_serve(stream, first[0], auth, outbound).await
    } else {
        http_serve(stream, first[0], outbound).await
    };
    if let Err(e) = result {
        eprintln!("lavray-engine: соединение закрыто: {e}");
    }
}

async fn socks_serve(
    stream: TcpStream,
    first: u8,
    auth: Option<(&str, &str)>,
    outbound: Outbound,
) -> std::io::Result<()> {
    let mut s = Sniffed::new(stream, first);
    socks5::handshake(&mut s, auth).await?;
    let Some(target) = socks5::read_request(&mut s).await? else {
        return Ok(()); // не-CONNECT: отказ уже отправлен
    };
    let upstream = outbound.connect(&target).await;
    let stream = s.into_inner();
    let (cr, mut cw) = stream.into_split();
    match upstream {
        Ok(up) => {
            socks5::reply_ok(&mut cw).await?;
            let (ur, uw) = up.into_split();
            relay::pump(cr, cw, ur, uw, Vec::new()).await?;
            Ok(())
        }
        Err(e) => {
            let _ = socks5::reply_fail(&mut cw).await;
            Err(e)
        }
    }
}

async fn http_serve(stream: TcpStream, first: u8, outbound: Outbound) -> std::io::Result<()> {
    let mut s = Sniffed::new(stream, first);
    let Some((target, tail)) = http_connect::read_connect(&mut s).await? else {
        http_connect::reply_405(&mut s).await?;
        return Ok(());
    };
    let upstream = outbound.connect(&target).await;
    let stream = s.into_inner();
    let (cr, mut cw) = stream.into_split();
    match upstream {
        Ok(up) => {
            http_connect::reply_ok(&mut cw).await?;
            let (ur, uw) = up.into_split();
            relay::pump(cr, cw, ur, uw, tail).await?;
            Ok(())
        }
        Err(e) => {
            let _ = http_connect::reply_502(&mut cw).await;
            Err(e)
        }
    }
}

/// Цель соединения наружу (для логов/статистики в следующих волнах).
#[allow(dead_code)]
fn describe(target: &TargetAddr) -> String {
    target.to_string()
}
