// SPDX-License-Identifier: GPL-3.0-only

//! VLESS UDP-канал: TCP+TLS stream (cmd=2), пакеты [len16 BE][data]
//! в обе стороны (xray vless UDP-over-stream).

use crate::addr::TargetAddr;
use crate::relay::{UpRead, UpWrite};
use crate::udp_pipe::UdpPipe;
use crate::vless::client::{VlessOutbound, connect_udp as vless_connect_udp};
use std::io;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;

/// Писатель VLESS UDP (len16-префикс); разделяется Arc'ом.
pub struct UpWriteVless {
    pub(crate) inner: Arc<Mutex<UpWrite>>,
}

impl UpWriteVless {
    /// Обернуть writer-половину VLESS-стрима.
    pub(crate) fn new(inner: UpWrite) -> Self {
        Self {
            inner: Arc::new(Mutex::new(inner)),
        }
    }

    /// Отправить один пакет.
    ///
    /// # Errors
    /// I/O.
    pub async fn send(&self, data: &[u8]) -> io::Result<()> {
        let mut w = self.inner.lock().await;
        let len = u16::try_from(data.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "vless udp: пакет > 65535"))?;
        w.write_all(&len.to_be_bytes()).await?;
        w.write_all(data).await?;
        w.flush().await
    }
}

/// Читатель VLESS UDP: [len16][data] в поток.
///
/// # Errors
/// I/O.
pub async fn vless_recv(r: &mut UpRead) -> io::Result<Vec<u8>> {
    let mut hdr = [0u8; 2];
    r.read_exact(&mut hdr).await?;
    let len = u16::from_be_bytes(hdr);
    let mut data = vec![0u8; usize::from(len)];
    r.read_exact(&mut data).await?;
    Ok(data)
}

/// Подключить VLESS UDP-канал.
///
/// # Errors
/// I/O / TLS.
pub async fn vless_connect(o: &VlessOutbound, target: &TargetAddr) -> io::Result<UdpPipe> {
    let (r, w) = vless_connect_udp(o, target).await?;
    let w = Arc::new(UpWriteVless::new(w));
    Ok(UdpPipe::Vless(r, w, target.clone()))
}
