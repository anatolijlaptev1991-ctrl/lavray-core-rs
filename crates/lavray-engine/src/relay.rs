// SPDX-License-Identifier: GPL-3.0-only

//! Relay: двустороннее копирование байтов клиент ↔ цель с отправкой
//! «предзачитанного» хвоста (HTTP CONNECT читает голову чанками и может
//! захватить первые байты данных). Буферы — фиксированные на стеке задачи.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};

/// Размер буфера направления (паритет sing-box 16 КиБ).
const BUF: usize = 16 * 1024;
/// Идл-таймаут relay: без байтов в обе стороны так долго — соединение мёртво.
const IDLE: Duration = Duration::from_secs(300);

/// Копирует в обе стороны до EOF/ошибки; сперва пишет `prefix` в `up_w`.
/// Возвращает суммарное число байт (для статистики соединения).
pub async fn pump(
    mut down_r: OwnedReadHalf,
    mut down_w: OwnedWriteHalf,
    mut up_r: OwnedReadHalf,
    mut up_w: OwnedWriteHalf,
    prefix: Vec<u8>,
) -> std::io::Result<u64> {
    if !prefix.is_empty() {
        up_w.write_all(&prefix).await?;
    }
    // Буферы в куче: future остаётся компактной (клippy large_futures),
    // одна аллокация на соединение против 32 КиБ в стейт-машине select.
    let mut a2b = Box::new([0u8; BUF]);
    let mut b2a = Box::new([0u8; BUF]);
    let mut total = prefix.len() as u64;
    loop {
        tokio::select! {
            r = down_r.read(a2b.as_mut_slice()) => match r {
                Ok(0) | Err(_) => break, // клиент закрыл/ошибка — конец обоих
                Ok(n) => {
                    up_w.write_all(&a2b[..n]).await?;
                    total += n as u64;
                }
            },
            r = up_r.read(b2a.as_mut_slice()) => match r {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    down_w.write_all(&b2a[..n]).await?;
                    total += n as u64;
                }
            },
            () = tokio::time::sleep(IDLE) => {
                // Идл: закрываем обе стороны (shutdown пишущих половинок).
                let _ = up_w.shutdown().await;
                let _ = down_w.shutdown().await;
                break;
            }
        }
    }
    let _ = up_w.shutdown().await;
    let _ = down_w.shutdown().await;
    Ok(total)
}
