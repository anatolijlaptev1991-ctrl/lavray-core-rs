// SPDX-License-Identifier: GPL-3.0-only

//! Изоляция VMess-тела: writer → TCP → reader (без заголовков/сервера).

use lavray_engine::vmess::body::BodyReader;
use lavray_engine::vmess::header::Security;
use lavray_engine::vmess::write::BodyWriter;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[tokio::test(flavor = "multi_thread")]
async fn body_roundtrip_two_chunks() {
    let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = ln.local_addr().unwrap();
    let key = [3u8; 16];
    let nonce = [4u8; 16];

    // Эхо-сторона: читает writer-байты сырым сокетом и возвращает их же
    // (loopback — reader будет расшифровывать собственные блоки:
    //  ключи/нонсы симметричны → должно сойтись).
    tokio::spawn(async move {
        let (mut s, _) = ln.accept().await.unwrap();
        let mut buf = vec![0u8; 4096];
        loop {
            let n = s.read(&mut buf).await.unwrap_or(0);
            if n == 0 {
                break;
            }
            s.write_all(&buf[..n]).await.unwrap();
        }
    });

    let sock = tokio::net::TcpStream::connect(addr).await.unwrap();
    let (r, w) = sock.into_split();
    let mut wr = BodyWriter::new(w, Security::Aes128Gcm, &key, &nonce, None);
    let mut rd = BodyReader::new(r, Security::Aes128Gcm, &key, &nonce);

    wr.write_all(b"first").await.unwrap();
    wr.write_all(b"-second").await.unwrap();
    let mut got = Vec::new();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    while got.len() < 12 {
        let mut piece = [0u8; 12];
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        let n = tokio::time::timeout(left, rd.read(&mut piece))
            .await
            .expect("timeout")
            .unwrap();
        assert!(n > 0);
        got.extend_from_slice(&piece[..n]);
    }
    assert_eq!(&got, b"first-second");
}
