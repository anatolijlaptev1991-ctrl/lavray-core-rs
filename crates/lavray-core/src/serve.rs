// SPDX-License-Identifier: GPL-3.0-only

//! `serve`: паритет запуска Go-ядра — токен из stdin (первая строка;
//! вторая — агентский MCP-токен, может не прийти), слушатель
//! UDS/127.0.0.1, gRPC (tonic) с сервисами Settings/Profile/Routing,
//! mixed-инбаунд из настроек хранилища (outbound Direct до интеграции
//! профилей — волна 7g+), готовность — LAVRAY_CORE_READY.

use std::sync::Arc;

use lavray_proto::v1::profile_service_server::ProfileServiceServer;
use lavray_proto::v1::routing_service_server::RoutingServiceServer;
use lavray_proto::v1::settings_service_server::SettingsServiceServer;
use lavray_store::Store;
use tokio::io::AsyncBufReadExt;

/// Разобрать флаги serve; ошибка — сообщение (код 2).
fn parse_args(args: &[String]) -> Result<(String, String), String> {
    let mut listen = String::new();
    let mut data = default_data_dir();
    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        let value = |i: &mut usize| -> Result<String, String> {
            *i += 1;
            args.get(*i)
                .cloned()
                .ok_or_else(|| format!("{arg} требует значение"))
        };
        match arg {
            "--listen-socket" => listen = value(&mut i)?,
            "--data" => data = value(&mut i)?,
            other => return Err(format!("неизвестный флаг {other:?}")),
        }
        i += 1;
    }
    if listen.is_empty() {
        return Err("--listen-socket обязателен".into());
    }
    Ok((listen, data))
}

/// Каталог данных по умолчанию: ./data рядом с бинарём.
fn default_data_dir() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|p| {
            p.parent()
                .map(|d| d.join("data").to_string_lossy().into_owned())
        })
        .unwrap_or_else(|| "data".into())
}

/// Точка входа serve; код возврата процесса.
pub fn run(args: &[String]) -> i32 {
    let (listen, data) = match parse_args(args) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("lavray-core serve: {e}");
            return 2;
        }
    };
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    rt.block_on(serve(listen, data))
}

async fn serve(listen: String, data: String) -> i32 {
    // §3.2: токены из stdin (первая строка — auth; вторая — агентский
    // MCP, может не прийти). Ошибка чтения — код 1.
    if let Err(e) = read_startup_stdin().await {
        eprintln!("lavray-core: {e}");
        return 1;
    }

    // Хранилище.
    let dir = std::path::Path::new(&data);
    if let Err(e) = std::fs::create_dir_all(dir) {
        eprintln!("lavray-core: каталог данных {data:?}: {e}");
        return 1;
    }
    let store = match Store::open(&dir.join("lavray.db")) {
        Ok(s) => Arc::new(std::sync::Mutex::new(s)),
        Err(e) => {
            eprintln!("lavray-core: store: {e}");
            return 1;
        }
    };

    // Mixed-инбаунд из настроек; отказ (порт занят) — фатально, как Go.
    let (bind_addr, bind_port) = mixed_bind(&store);
    let inbound = match lavray_engine::start(lavray_engine::MixedConfig {
        listen: format!("{bind_addr}:{bind_port}"),
        socks_auth: None,
        outbound: lavray_engine::Outbound::Direct,
    })
    .await
    {
        Ok(s) => s,
        Err(e) => {
            eprintln!("lavray-core: mixed-inbound: {e}");
            return 1;
        }
    };

    if let Err(e) = crate::listener::bind_and_serve(build_router(store), &listen).await {
        eprintln!("lavray-core: {e}");
        return 1;
    }
    inbound.stop();
    0
}

/// Собрать gRPC-роутер с реализованными сервисами (волна 7g MVP).
pub(super) fn build_router(
    store: Arc<std::sync::Mutex<Store>>,
) -> tonic::transport::server::Router {
    tonic::transport::Server::builder()
        .add_service(SettingsServiceServer::new(
            lavray_api::SettingsServiceImpl::new(Arc::clone(&store)),
        ))
        .add_service(ProfileServiceServer::new(
            lavray_api::ProfileServiceImpl::new(Arc::clone(&store)),
        ))
        .add_service(RoutingServiceServer::new(
            lavray_api::RoutingServiceImpl::new(store),
        ))
}

/// Строка готовности (оболочка ждёт её после spawn).
pub(super) fn ready() {
    println!("LAVRAY_CORE_READY");
    let _ = std::io::Write::flush(&mut std::io::stdout());
}

/// Стартовый auth-токен из stdin. Агентская строка (вторая, MCP) может не
/// прийти вовсе — читается ФОНОВО и запуск не блокирует (паритет Go
/// agentTokenCh; сохранение агентского токена — волна 7g+).
async fn read_startup_stdin() -> std::io::Result<String> {
    let mut stdin = tokio::io::BufReader::new(tokio::io::stdin());
    let mut token = String::new();
    if stdin.read_line(&mut token).await? == 0 {
        return Err(std::io::Error::other("auth-токен не получен (stdin)"));
    }
    tokio::spawn(async move {
        let mut line = String::new();
        loop {
            line.clear();
            match stdin.read_line(&mut line).await {
                Ok(0) | Err(_) => break, // EOF = смерть оболочки
                Ok(_) => {}
            }
        }
    });
    let token = token.trim_end_matches(['\r', '\n']).to_string();
    if token.is_empty() {
        eprintln!("lavray-core: auth-токен пуст: запросы будут отклоняться (fail-closed)");
    }
    Ok(token)
}

/// Адрес/порт mixed из настроек; дефолт Go — 127.0.0.1:2080.
fn mixed_bind(store: &Arc<std::sync::Mutex<Store>>) -> (String, u16) {
    let st = store
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let addr = st
        .get_setting("inbound.address")
        .ok()
        .flatten()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_else(|| "127.0.0.1".into());
    let port = st
        .get_setting("inbound.port")
        .ok()
        .flatten()
        .and_then(|v| v.as_u64())
        .and_then(|v| u16::try_from(v).ok())
        .unwrap_or(2080);
    (addr, port)
}
