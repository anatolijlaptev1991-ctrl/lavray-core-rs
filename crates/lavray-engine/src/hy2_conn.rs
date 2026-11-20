// SPDX-License-Identifier: GPL-3.0-only

//! Hysteria2-клиент: QUIC-соединение, HTTP/3-минимум (control + QPACK
//! uni-потоки + auth POST /auth, статус 233) и TCP-поток 0x401.
//! Паритет Go sing-quic/hysteria2 clientConn.

use std::net::SocketAddr;

use crate::h3_auth::{read_h3_auth_response, send_h3_auth};
use crate::hy2::{read_varint_stream, write_tcp_request};
use crate::hy2_config::{Hy2Config, Hy2Error, write_varint};
use crate::hy2_stream::Hy2Stream;

/// Подключение к hysteria2: QUIC + auth (HTTP/3-минимум) → открытый
/// TCP-поток к `host:port`; `first_payload` уходит в первом write
/// (parity Go clientConn.Write: request+payload одним куском).
///
/// # Errors
/// I/O / TLS / auth (код != 233).
pub async fn connect_with_payload(
    cfg: &Hy2Config,
    host: &str,
    port: u16,
    first_payload: &[u8],
) -> Result<Hy2Stream, Hy2Error> {
    let client_cfg = crate::quic_tls::client_config(cfg.skip_verify, &["h3"])
        .map_err(|e| Hy2Error(e.clone()))?;

    let addr = SocketAddr::new(
        cfg.server
            .parse()
            .map_err(|_| Hy2Error("bad server ip (только IP; DNS — 7f-3c-4)".into()))?,
        cfg.server_port,
    );
    let mut endpoint = quinn::Endpoint::client(
        "0.0.0.0:0"
            .parse()
            .map_err(|e| Hy2Error(format!("bind: {e}")))?,
    )
    .map_err(|e| Hy2Error(format!("endpoint: {e}")))?;
    endpoint.set_default_client_config(client_cfg);
    let conn = endpoint
        .connect(addr, &cfg.sni)
        .map_err(|e| Hy2Error(format!("connect: {e}")))?
        .await
        .map_err(|e| Hy2Error(format!("quic handshake: {e}")))?;

    let (control, qpack_enc, qpack_dec) = open_h3_streams(&conn).await?;
    auth(&conn, cfg).await?;
    let (send, recv) = open_tcp_stream(&conn, host, port, first_payload).await?;
    Ok(Hy2Stream {
        conn,
        control,
        qpack_enc,
        qpack_dec,
        send,
        recv,
    })
}

/// H3-минимум: control с пустым SETTINGS (RFC 9114 §7.2.4: первый
/// uni-поток клиента обязан быть control; без него h3-стек сервера
/// отклоняет bi-запросы) + QPACK encoder/decoder потоки (RFC 9204 §4.2).
/// Потоки НЕ закрываем — по спеке живут всё соединение (держим в
/// Hy2Stream); динамическая таблица не используется, инструкции пусты.
async fn open_h3_streams(
    conn: &quinn::Connection,
) -> Result<(quinn::SendStream, quinn::SendStream, quinn::SendStream), Hy2Error> {
    let mut control = conn
        .open_uni()
        .await
        .map_err(|e| Hy2Error(format!("open control: {e}")))?;
    let mut settings = Vec::with_capacity(2);
    write_varint(&mut settings, 0x0); // SETTINGS
    write_varint(&mut settings, 0); // пустой payload
    control
        .write_all(&settings)
        .await
        .map_err(|e| Hy2Error(format!("write control: {e}")))?;

    let mut qenc = conn
        .open_uni()
        .await
        .map_err(|e| Hy2Error(format!("open qpack enc: {e}")))?;
    qenc.write_all(&[0x02])
        .await
        .map_err(|e| Hy2Error(format!("write qpack enc: {e}")))?;
    let mut qdec = conn
        .open_uni()
        .await
        .map_err(|e| Hy2Error(format!("open qpack dec: {e}")))?;
    qdec.write_all(&[0x03])
        .await
        .map_err(|e| Hy2Error(format!("write qpack dec: {e}")))?;
    Ok((control, qenc, qdec))
}

/// Auth: HTTP/3 POST /auth с Hysteria-заголовками (status 233 = ok).
async fn auth(conn: &quinn::Connection, cfg: &Hy2Config) -> Result<(), Hy2Error> {
    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .map_err(|e| Hy2Error(format!("open bi: {e}")))?;
    send_h3_auth(&mut send, &cfg.password, cfg.rx_bps)
        .await
        .map_err(Hy2Error)?;
    if !read_h3_auth_response(&mut recv)
        .await
        .map_err(|e| Hy2Error(e.clone()))?
    {
        conn.close(0u32.into(), b"auth failed");
        return Err(Hy2Error("authentication failed (status != 233)".into()));
    }
    Ok(())
}

/// Открыть bi-стрим под TCP-запрос: 0x401 + addr + padding + payload.
async fn open_tcp_stream(
    conn: &quinn::Connection,
    host: &str,
    port: u16,
    first_payload: &[u8],
) -> Result<(quinn::SendStream, quinn::RecvStream), Hy2Error> {
    let (mut req_send, mut req_recv) = conn
        .open_bi()
        .await
        .map_err(|e| Hy2Error(format!("open tcp stream: {e}")))?;
    let addr = format!("{host}:{port}");
    let first = write_tcp_request(&addr, first_payload);
    req_send
        .write_all(&first)
        .await
        .map_err(|e| Hy2Error(format!("write request: {e}")))?;
    // TCPResponse читаем побайтово точно (status + msg_len + msg +
    // pad_len + pad), не затрагивая данные, приехавшие в том же
    // QUIC-пакете, что и response.
    read_tcp_response_exact(&mut req_recv).await?;

    Ok((req_send, req_recv))
}

/// Точное чтение TCPResponse из потока по одному полю — данные после
/// response остаются в потоке для Hy2Stream.
///
/// # Errors
/// I/O / статус != 0.
async fn read_tcp_response_exact(recv: &mut quinn::RecvStream) -> Result<(), Hy2Error> {
    let mut status = [0u8; 1];
    recv.read_exact(&mut status)
        .await
        .map_err(|e| Hy2Error(format!("read status: {e}")))?;
    if status[0] != 0 {
        // ошибка удалённой стороны: msg_len + msg
        let (msg_len, _) = read_varint_stream(recv).await?;
        let mut msg = vec![0u8; usize::try_from(msg_len).unwrap_or(0)];
        recv.read_exact(&mut msg)
            .await
            .map_err(|e| Hy2Error(format!("read msg: {e}")))?;
        let text = String::from_utf8_lossy(&msg);
        return Err(Hy2Error(format!("remote error: {text}")));
    }
    let (msg_len, _) = read_varint_stream(recv).await?;
    let mut msg = vec![0u8; usize::try_from(msg_len).unwrap_or(0)];
    recv.read_exact(&mut msg)
        .await
        .map_err(|e| Hy2Error(format!("read msg: {e}")))?;
    let (pad_len, _) = read_varint_stream(recv).await?;
    let mut pad = vec![0u8; usize::try_from(pad_len).unwrap_or(0)];
    recv.read_exact(&mut pad)
        .await
        .map_err(|e| Hy2Error(format!("read pad: {e}")))?;
    Ok(())
}
