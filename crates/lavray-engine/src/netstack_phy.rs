// SPDX-License-Identifier: GPL-3.0-only

//! Rx/TxToken: smoltcp-адаптер поверх TunIo очередей.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

pub(crate) struct RxToken {
    buffer: Vec<u8>,
}

impl smoltcp::phy::RxToken for RxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        f(&mut { self.buffer })
    }
}

pub(crate) struct TxToken {
    pub(crate) queue: Arc<Mutex<VecDeque<Vec<u8>>>>,
}

impl smoltcp::phy::TxToken for TxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut pkt = vec![0u8; len];
        let result = f(&mut pkt);
        if let Ok(mut q) = self.queue.lock() {
            q.push_back(pkt);
        }
        result
    }
}

/// Конструктор RxToken (для netstack.rs).
pub(crate) fn rx_token(buffer: Vec<u8>) -> RxToken {
    RxToken { buffer }
}
