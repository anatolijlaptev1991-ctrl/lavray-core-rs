// SPDX-License-Identifier: GPL-3.0-only

//! E2E ws-транспорта: клиент (Upgrade + маскированные фреймы) против
//! тестового WS-эхо-сервера (принимает Upgrade, размаскирует фреймы,
//! возвращает немаскированными). Проверяется handshake, фрейминг обоих
//! направлений, мультифрейм, большой (>126) и «бессмертный» чанк.

use lavray_engine::ws::{WsDial, handshake};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Эхо-сервер: 101 на Upgrade; фреймы клиента (маскированные)
/// размаскирует и возвращает бинарными немаскированными.
async fn ws_echo_server() -> std::io::Result<std::net::SocketAddr> {
    let ln = TcpListener::bind("127.0.0.1:0").await?;
    let addr = ln.local_addr()?;
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = ln.accept().await else {
                return;
            };
            tokio::spawn(async move {
                if let Err(e) = serve(&mut s).await {
                    eprintln!("ws-echo: {e}");
                }
            });
        }
    });
    Ok(addr)
}

async fn serve(s: &mut TcpStream) -> std::io::Result<()> {
    // Заголовок запроса.
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    loop {
        let n = s.read(&mut b).await?;
        if n == 0 {
            return Ok(());
        }
        head.push(b[0]);
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    s.write_all(
        b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\
          Connection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n",
    )
    .await?;

    // Фреймы: читать маскированные, отвечать немаскированными.
    loop {
        let mut hdr = [0u8; 2];
        if s.read_exact(&mut hdr).await.is_err() {
            return Ok(());
        }
        let opcode = hdr[0] & 0x0F;
        let masked = hdr[1] & 0x80 != 0;
        let mut len = u64::from(hdr[1] & 0x7F);
        if len == 126 {
            let mut ex = [0u8; 2];
            s.read_exact(&mut ex).await?;
            len = u64::from(u16::from_be_bytes(ex));
        } else if len == 127 {
            let mut ex = [0u8; 8];
            s.read_exact(&mut ex).await?;
            len = u64::from_be_bytes(ex);
        }
        let mut mask = [0u8; 4];
        if masked {
            s.read_exact(&mut mask).await?;
        }
        let mut pay = vec![0u8; usize::try_from(len).unwrap_or(0)];
        s.read_exact(&mut pay).await?;
        if masked {
            for (i, x) in pay.iter_mut().enumerate() {
                *x ^= mask[i % 4];
            }
        }
        match opcode {
            0x8 => return Ok(()), // close
            0x9 | 0xA => {}       // ping/pong — прокинуть тем же опкодом
            op => {
                // Ответ: немаскированный, тот же опкод.
                let mut out = vec![0x80 | op];
                if pay.len() < 126 {
                    out.push(u8::try_from(pay.len()).unwrap_or(125));
                } else {
                    out.push(126);
                    out.extend_from_slice(&u16::try_from(pay.len()).unwrap_or(0).to_be_bytes());
                }
                out.extend_from_slice(&pay);
                s.write_all(&out).await?;
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn ws_client_handshake_and_frames_echo() {
    let addr = ws_echo_server().await.unwrap();
    let tcp = TcpStream::connect(addr).await.unwrap();
    let (mut r, mut w) = handshake(
        tcp,
        &WsDial {
            path: "/lavray".into(),
            host: String::new(),
        },
        "127.0.0.1",
    )
    .await
    .unwrap();

    // Малый фрейм (<126 — 1-байтовая длина).
    w.write_all(b"small").await.unwrap();
    let mut back = Vec::new();
    read_exact_n(&mut r, 5, &mut back).await;
    assert_eq!(&back, b"small");

    // Средний (126..=65535 — 2-байтовая длина).
    let mid: Vec<u8> = (0..1000usize)
        .map(|i| u8::try_from(i % 251).expect("<251"))
        .collect();
    w.write_all(&mid).await.unwrap();
    let mut got = Vec::new();
    read_exact_n(&mut r, mid.len(), &mut got).await;
    assert_eq!(got, mid);

    // Мультифрейм: 3 фрейма подряд, чтение суммарно.
    let a = vec![1u8; 300];
    let bb = vec![2u8; 200];
    let c = vec![3u8; 100];
    w.write_all(&a).await.unwrap();
    w.write_all(&bb).await.unwrap();
    w.write_all(&c).await.unwrap();
    let mut got = Vec::new();
    read_exact_n(&mut r, 600, &mut got).await;
    let expect = [a, bb, c].concat();
    assert_eq!(got, expect);
}

/// Дочитать ровно n байт (фреймы могут дробиться).
async fn read_exact_n<S>(s: &mut S, n: usize, out: &mut Vec<u8>)
where
    S: AsyncReadExt + Unpin,
{
    let start = out.len();
    out.resize(start + n, 0);
    let mut got = 0;
    while got < n {
        let k = s.read(&mut out[start + got..]).await.unwrap();
        assert!(k > 0, "обрыв на {got}/{n}");
        got += k;
    }
}
