// SPDX-License-Identifier: GPL-3.0-only

//! Relay-пайплайн poll-цикла TUN: клиентские данные (из smoltcp-сокета,
//! вычитывает poll-цикл) уходят в канал upstream-задачи; ответы upstream
//! — обратным каналом в poll-цикл (send_slice). Полный двунаправленный
//! relay: цикл никогда не ждёт EOF.

use crate::addr::TargetAddr;
use crate::tun_outbound::Outbound;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

/// Сообщение upstream-задачи poll-циклу.
pub enum ToClient {
    /// Данные для клиента.
    Data(Vec<u8>),
    /// Upstream закрылся (клиентский сокет закрывается).
    Eof,
}

/// Состояние проксируемого соединения.
pub struct FlowState {
    /// Цель (dst из SYN).
    pub target: TargetAddr,
    /// Данные клиента → upstream-задаче.
    pub to_up: mpsc::UnboundedSender<Vec<u8>>,
    /// Upstream-задача → клиенту.
    pub from_up: mpsc::UnboundedReceiver<ToClient>,
}

/// Запустить upstream-задачу для нового соединения.
pub fn spawn_upstream(outbound: Arc<Outbound>, target: TargetAddr) -> FlowState {
    let (to_up, to_up_rx) = mpsc::unbounded_channel();
    let (from_up_tx, from_up_rx) = mpsc::unbounded_channel();
    tokio::spawn(upstream_task(
        outbound,
        target.clone(),
        to_up_rx,
        from_up_tx,
    ));
    FlowState {
        target,
        to_up,
        from_up: from_up_rx,
    }
}

/// Тело upstream-задачи: connect + перекачка обоих направлений в select.
async fn upstream_task(
    outbound: Arc<Outbound>,
    target: TargetAddr,
    mut to_up: mpsc::UnboundedReceiver<Vec<u8>>,
    from_up: mpsc::UnboundedSender<ToClient>,
) {
    let Ok(mut up) = outbound.connect(&target).await else {
        let _ = from_up.send(ToClient::Eof);
        return;
    };
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        tokio::select! {
            data = to_up.recv() => {
                match data {
                    Some(d) if !d.is_empty() => {
                        if up.write_all(&d).await.is_err() {
                            let _ = from_up.send(ToClient::Eof);
                            return;
                        }
                        if up.flush().await.is_err() {
                            let _ = from_up.send(ToClient::Eof);
                            return;
                        }
                    }
                    // канал закрыт (клиент закрылся) или пустой чанк
                    _ => break,
                }
            }
            n = up.read(&mut buf) => {
                match n {
                    Ok(0) | Err(_) => {
                        let _ = from_up.send(ToClient::Eof);
                        return;
                    }
                    Ok(n) => {
                        if from_up.send(ToClient::Data(buf[..n].to_vec())).is_err() {
                            return;
                        }
                    }
                }
            }
        }
    }
    // канал клиента закрыт: upstream закрывается (EOF для poll-цикла)
    let _ = from_up.send(ToClient::Eof);
}

/// Утилита: обработать вычитанные ответы upstream и отметить EOF.
///
/// Возвращает true, если flow должен быть закрыт (upstream EOF).
pub fn drain_to_client(
    flow: &mut FlowState,
    mut send_slice: impl FnMut(&[u8]) -> Result<usize, String>,
    close: &mut dyn FnMut(),
) -> bool {
    let mut closed = false;
    while let Ok(msg) = flow.from_up.try_recv() {
        match msg {
            ToClient::Data(d) => {
                let mut off = 0;
                while off < d.len() {
                    match send_slice(&d[off..]) {
                        Ok(n) => off += n,
                        Err(_) => return true, // сокет мёртв
                    }
                }
            }
            ToClient::Eof => {
                if !closed {
                    close();
                    closed = true;
                }
            }
        }
    }
    closed
}
