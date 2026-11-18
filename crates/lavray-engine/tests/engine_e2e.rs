// SPDX-License-Identifier: GPL-3.0-only

//! E2E волны 7a: сквозной трафик через mixed-прокси — эхо-сервер как цель,
//! клиенты SOCKS5 и HTTP CONNECT, включая tail-байты после головы CONNECT
//! (критично: клиент шлёт данные сразу). Всё на loopback, без интернета.

mod common;

use common::{echo_server, proxy};
use lavray_engine::{MixedConfig, start};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[tokio::test]
async fn socks5_roundtrip_echo() {
    let echo = echo_server().await.unwrap();
    let (px, _srv) = proxy().await;
    let mut c = TcpStream::connect(px).await.unwrap();

    // handshake: no-auth
    c.write_all(&[0x05, 1, 0x00]).await.unwrap();
    let mut m = [0u8; 2];
    c.read_exact(&mut m).await.unwrap();
    assert_eq!(m, [0x05, 0x00]);

    // CONNECT на домен 127.0.0.1 (ATYP=домен — резолв системный)
    let mut req = vec![0x05, 0x01, 0x00, 0x03, 9];
    req.extend_from_slice(b"127.0.0.1");
    req.extend_from_slice(&echo.port().to_be_bytes());
    c.write_all(&req).await.unwrap();
    let mut rep = [0u8; 10]; // VER REP RSV ATYP=IPv4 BND(4) PORT(2)
    c.read_exact(&mut rep).await.unwrap();
    assert_eq!(&rep[..2], &[0x05, 0x00], "reply: {rep:02x?}");

    // данные туда-обратно
    c.write_all(b"hello").await.unwrap();
    let mut back = [0u8; 5];
    c.read_exact(&mut back).await.unwrap();
    let inverted: Vec<u8> = b"hello".iter().map(|b| !*b).collect();
    assert_eq!(&back, inverted.as_slice());
}

#[tokio::test]
async fn socks5_userpass_ok_and_fail() {
    let echo = echo_server().await.unwrap();
    let srv = start(MixedConfig {
        listen: "127.0.0.1:0".into(),
        socks_auth: Some(("u".into(), "p".into())),
        ..Default::default()
    })
    .await
    .unwrap();
    let px = srv.local_addr();

    // Верный пароль: полный roundtrip.
    let mut c = TcpStream::connect(px).await.unwrap();
    c.write_all(&[0x05, 1, 0x02]).await.unwrap();
    let mut m = [0u8; 2];
    c.read_exact(&mut m).await.unwrap();
    assert_eq!(m, [0x05, 0x02]);
    c.write_all(&[1, 1, b'u', 1, b'p']).await.unwrap();
    let mut st = [0u8; 2];
    c.read_exact(&mut st).await.unwrap();
    assert_eq!(st, [1, 0]);
    let mut req = vec![0x05, 0x01, 0x00, 0x01];
    req.extend_from_slice(&[127, 0, 0, 1]);
    req.extend_from_slice(&echo.port().to_be_bytes());
    c.write_all(&req).await.unwrap();
    let mut rep = [0u8; 10];
    c.read_exact(&mut rep).await.unwrap();
    assert_eq!(&rep[..2], &[0x05, 0x00]);
    c.write_all(b"ping").await.unwrap();
    let mut back = [0u8; 4];
    c.read_exact(&mut back).await.unwrap();
    assert_eq!(back, [!b'p', !b'i', !b'n', !b'g']);

    // Неверный пароль: сервер отвечает статусом 1 и закрывает.
    let mut c = TcpStream::connect(px).await.unwrap();
    c.write_all(&[0x05, 1, 0x02]).await.unwrap();
    c.read_exact(&mut [0u8; 2]).await.unwrap();
    c.write_all(&[1, 1, b'u', 2, b'x', b'y']).await.unwrap();
    let mut st = [0u8; 2];
    c.read_exact(&mut st).await.unwrap();
    assert_eq!(st, [1, 1]);
}

#[tokio::test]
async fn http_connect_roundtrip_with_tail() {
    let echo = echo_server().await.unwrap();
    let (px, _srv) = proxy().await;
    let mut c = TcpStream::connect(px).await.unwrap();

    // CONNECT + сразу хвост данных (TLS ClientHello-модель: без ожидания 2xx).
    let head = format!(
        "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: x\r\n\r\n",
        echo.port()
    );
    let mut msg = head.into_bytes();
    msg.extend_from_slice(b"early");
    c.write_all(&msg).await.unwrap();

    let mut line = Vec::new();
    let mut b = [0u8; 1];
    loop {
        c.read_exact(&mut b).await.unwrap();
        line.push(b[0]);
        if line.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    assert!(
        line.starts_with(b"HTTP/1.1 200"),
        "{}",
        String::from_utf8_lossy(&line)
    );

    // Хвост «early» дошёл до эха первым, затем обычный обмен.
    let mut back = [0u8; 5];
    c.read_exact(&mut back).await.unwrap();
    let inverted: Vec<u8> = b"early".iter().map(|b| !*b).collect();
    assert_eq!(&back, inverted.as_slice());
    c.write_all(b"late").await.unwrap();
    let mut back = [0u8; 4];
    c.read_exact(&mut back).await.unwrap();
    assert_eq!(back, [!b'l', !b'a', !b't', !b'e']);
}

#[tokio::test]
async fn http_non_connect_gets_405() {
    let (_px, srv) = proxy().await;
    let mut c = TcpStream::connect(srv.local_addr()).await.unwrap();
    c.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .unwrap();
    let mut resp = [0u8; 12];
    c.read_exact(&mut resp).await.unwrap();
    assert!(resp.starts_with(b"HTTP/1.1 405"));
}

#[tokio::test]
async fn socks5_unreachable_target_gets_general_fail() {
    let (px, _srv) = proxy().await;
    let mut c = TcpStream::connect(px).await.unwrap();
    c.write_all(&[0x05, 1, 0x00]).await.unwrap();
    c.read_exact(&mut [0u8; 2]).await.unwrap();
    // Порт 1 на loopback: connect откажет → REP=0x01.
    let mut req = vec![0x05, 0x01, 0x00, 0x01];
    req.extend_from_slice(&[127, 0, 0, 1]);
    req.extend_from_slice(&1u16.to_be_bytes());
    c.write_all(&req).await.unwrap();
    let mut rep = [0u8; 10];
    c.read_exact(&mut rep).await.unwrap();
    assert_eq!(rep[1], 0x01, "REP: {rep:02x?}");
}

#[tokio::test]
async fn stop_closes_listener_and_counts_active() {
    let echo = echo_server().await.unwrap();
    let srv = start(MixedConfig {
        listen: "127.0.0.1:0".into(),
        ..Default::default()
    })
    .await
    .unwrap();
    let px = srv.local_addr();

    // Долгоживущее соединение: connected через прокси, ждём.
    let mut c = TcpStream::connect(px).await.unwrap();
    c.write_all(&[0x05, 1, 0x00]).await.unwrap();
    c.read_exact(&mut [0u8; 2]).await.unwrap();
    let mut req = vec![0x05, 0x01, 0x00, 0x01];
    req.extend_from_slice(&[127, 0, 0, 1]);
    req.extend_from_slice(&echo.port().to_be_bytes());
    c.write_all(&req).await.unwrap();
    c.read_exact(&mut [0u8; 10]).await.unwrap();
    // даём спавну инкрементировать счётчик
    for _ in 0..50 {
        if srv.active() == 1 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert_eq!(srv.active(), 1);

    srv.stop();
    srv.join().await;
    // Слушатель закрыт: новый connect отказывает.
    assert!(TcpStream::connect(px).await.is_err());
    drop(c);
}
