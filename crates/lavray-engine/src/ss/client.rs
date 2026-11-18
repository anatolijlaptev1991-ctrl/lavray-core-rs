// SPDX-License-Identifier: GPL-3.0-only

//! SS-клиент (исходящий туннель): TCP к серверу, соль, сессионный ключ,
//! половины-шифраторы; адрес цели уходит первым полезным payload-ом.

use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use crate::addr::TargetAddr;
use crate::ss::aead::Method;
use crate::ss::key::{identity_key, session_key};
use crate::ss::stream::SsReadHalf;
use crate::ss::target::target_bytes;
use crate::ss::write::SsWriteHalf;

/// Параметры исходящего SS-туннеля.
#[derive(Debug, Clone)]
pub struct SsOutbound {
    /// Адрес SS-сервера.
    pub server: TargetAddr,
    /// Метод (строка из профиля, провалидирован).
    pub method: Method,
    /// Пароль (2022 — base64 ключа).
    pub password: String,
}

/// Установить SS-туннель к цели (salt → session → половины).
pub async fn connect(
    o: &SsOutbound,
    target: &TargetAddr,
) -> std::io::Result<(SsReadHalf, SsWriteHalf)> {
    let host = o.server.host_string();
    let stream = tokio::time::timeout(
        Duration::from_secs(5),
        TcpStream::connect((host.as_str(), o.server.port())),
    )
    .await
    .map_err(|_| std::io::Error::other(format!("connect {}: таймаут 5s", o.server)))??;
    let stream = stream;
    let _ = stream.set_nodelay(true);

    let identity = identity_key(o.method, &o.password);
    // Соль: криптостойкие байты ОС.
    let mut salt = vec![0u8; o.method.salt_len()];
    getrandom::fill(&mut salt).map_err(|e| std::io::Error::other(format!("соль: {e}")))?;
    let session = session_key(o.method, &identity, &salt);
    let (r, mut w) = stream.into_split();
    w.write_all(&salt).await?;
    Ok((
        SsReadHalf::new(r, o.method, &session),
        SsWriteHalf::new(w, o.method, &session, Some(target_bytes(target))),
    ))
}
