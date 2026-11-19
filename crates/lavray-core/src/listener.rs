// SPDX-License-Identifier: GPL-3.0-only

//! Слушатель serve: unix://… или TCP; bind прошёл → печать
//! LAVRAY_CORE_READY → gRPC serve.

use std::io;

use crate::serve::ready;
use tokio::net::TcpListener;

/// Bind + serve; готовность печатается после успешного bind.
pub(super) async fn bind_and_serve(
    router: tonic::transport::server::Router,
    listen: &str,
) -> io::Result<()> {
    if let Some(path) = listen.strip_prefix("unix://") {
        #[cfg(unix)]
        {
            let _ = std::fs::remove_file(path);
            let uds = tokio::net::UnixListener::bind(path)?;
            ready();
            router
                .serve_with_incoming(tokio_stream::wrappers::UnixListenerStream::new(uds))
                .await
                .map_err(|e| io::Error::other(format!("gRPC сервер: {e}")))
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            Err(io::Error::other(
                "unix-сокеты не поддерживаются на этой платформе",
            ))
        }
    } else {
        let tcp = TcpListener::bind(listen).await?;
        ready();
        router
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(tcp))
            .await
            .map_err(|e| io::Error::other(format!("gRPC сервер: {e}")))
    }
}
