// SPDX-License-Identifier: GPL-3.0-only

//! Читатель TUN: блокирующий read_packet — в выделенном std-потоке,
//! пакеты → unbounded-канал → асинхронный poll-цикл (ChannelTun).
//! Запись — через Arc<Mutex<TunIo>> (TUN-write не блокирует).

use crate::netstack_types::TunIo;
use std::io;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

/// TUN поверх канала читателя.
pub struct ChannelTun {
    rx: mpsc::UnboundedReceiver<Vec<u8>>,
    writer: Arc<Mutex<Box<dyn TunIo>>>,
}

impl TunIo for ChannelTun {
    fn read_packet(&mut self) -> io::Result<Vec<u8>> {
        match self.rx.try_recv() {
            Ok(p) => Ok(p),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty) => Ok(Vec::new()),
            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "tun reader закрыт",
            )),
        }
    }

    fn write_packet(&mut self, pkt: &[u8]) -> io::Result<()> {
        self.writer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .write_packet(pkt)
    }
}

/// Забрать владение TUN: блокирующий read → поток, запись → ChannelTun.
/// Возвращает ChannelTun (в netstack) — poll-цикл живёт в async-задаче.
pub fn spawn_reader(tun: Box<dyn TunIo>) -> ChannelTun {
    let tun = Arc::new(Mutex::new(tun));
    let (tx, rx) = mpsc::unbounded_channel();
    let reader = Arc::clone(&tun);
    std::thread::spawn(move || {
        loop {
            let mut t = reader
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Ok(p) = t.read_packet() {
                drop(t);
                if tx.send(p).is_err() {
                    break;
                }
            } else {
                let _ = tx.send(Vec::new()); // сигнал: девайс мёртв
                break;
            }
        }
    });
    ChannelTun { rx, writer: tun }
}
