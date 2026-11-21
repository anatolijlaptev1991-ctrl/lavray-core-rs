// SPDX-License-Identifier: GPL-3.0-only

//! Интеграционный тест бинаря: полный протокол запуска оболочкой —
//! spawn → auth-токен первой строкой stdin (вторая — агентский MCP-токен,
//! может отсутствовать) → ожидание LAVRAY_CORE_READY → gRPC-вызов
//! (ListPresets) на loopback-порту из --listen-socket.

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};

use lavray_store::Store;
use tokio::net::TcpStream;

struct ChildPipe(Child);

impl Drop for ChildPipe {
    // Тестовый гард: явный kill+wait — процесс не остаётся зомби
    // (clippy zombify не видит wait за kill в Drop).
    #[allow(clippy::zombie_processes)]
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_lavray-core")
}

fn temp_dir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!(
        "lavray-core-cli-{tag}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Запустить serve на фиксированном свободном порту, скормить токены,
/// дождаться LAVRAY_CORE_READY; возвращает (child-гард, gRPC-адрес).
#[allow(clippy::zombie_processes)] // гард ChildPipe::drop делает kill+wait
fn launch(agent_token: Option<&str>) -> (ChildPipe, String, u16) {
    // Эфемерные порты — TOCTOU: на нагруженных раннерах (4 параллельных
    // теста, 3 ядра macOS) ОС может выдать один порт дважды → EADDRINUSE
    // → ядро умирает до READY. Ретраи с новыми портами/каталогами.
    for _ in 0..3 {
        if let Some(r) = launch_once(agent_token) {
            return r;
        }
    }
    panic!("serve не поднялся за 3 попытки (порт-гонки эфемерных портов)");
}

fn launch_once(agent_token: Option<&str>) -> Option<(ChildPipe, String, u16)> {
    let port = free_port();
    // Разные порты gRPC и mixed: защита от одинакового эфемерного порта.
    let mut inbound_port = free_port();
    while inbound_port == port {
        inbound_port = free_port();
    }
    let dir = temp_dir("serve");
    {
        let store = Store::open(&dir.join("lavray.db")).unwrap();
        store
            .set_setting("inbound.port", &serde_json::json!(inbound_port))
            .unwrap();
    }
    let mut child = Command::new(bin())
        .arg("serve")
        .arg("--listen-socket")
        .arg(format!("127.0.0.1:{port}"))
        .arg("--data")
        .arg(dir.to_string_lossy().as_ref())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn lavray-core");

    {
        let stdin = child.stdin.as_mut().expect("stdin");
        stdin
            .write_all(b"e2e-auth-token-0123456789abcdef\n")
            .unwrap();
        if let Some(agent) = agent_token {
            stdin.write_all(agent.as_bytes()).unwrap();
            stdin.write_all(b"\n").unwrap();
        }
        stdin.flush().unwrap();
        // stdin не закрываем: EOF = смерть оболочки → выход ядра.
    }

    // READY с таймаутом и детектом смерти ядра: порт-гонки под нагрузкой
    // параллельных тестов не должны вешать прогон навечно.
    let stdout = child.stdout.take().expect("stdout");
    let (tx, rx) = std::sync::mpsc::channel::<String>();
    std::thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    if tx.send(line.clone()).is_err() {
                        break;
                    }
                }
            }
        }
    });
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    loop {
        if child.try_wait().expect("try_wait").is_some() {
            eprintln!("lavray-core умер до LAVRAY_CORE_READY (порт-гонка?), ретрай");
            drop(ChildPipe(child));
            return None;
        }
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        if left.is_zero() {
            eprintln!("LAVRAY_CORE_READY не получен за 15 с, ретрай");
            drop(ChildPipe(child));
            return None;
        }
        if let Ok(line) = rx.recv_timeout(left.min(std::time::Duration::from_millis(300)))
            && line.trim() == "LAVRAY_CORE_READY"
        {
            return Some((
                ChildPipe(child),
                format!("http://127.0.0.1:{port}"),
                inbound_port,
            ));
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn serve_startup_protocol_and_listener() {
    // Полный протокол запуска: токен → READY → слушатель gRPC принимает
    // TCP (gRPC-wire-вызов — волна 7g+, клиентская генерация proto
    // отключена из-за RPC Connect; сервисы покрыты юнит-тестами api).
    let (_guard, addr, inbound_port) = launch(None);
    let addr = addr.trim_start_matches("http://").to_string();
    TcpStream::connect(&addr).await.unwrap();
    // Mixed-инбаунд поднялся на порту из настроек.
    TcpStream::connect(("127.0.0.1", inbound_port))
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn serve_startup_with_agent_token() {
    let (_guard, addr, _inbound) = launch(Some("agent-token-9876543210fedcba"));
    let addr = addr.trim_start_matches("http://").to_string();
    TcpStream::connect(&addr).await.unwrap();
}

#[test]
fn version_subcommand() {
    let out = Command::new(bin()).arg("version").output().unwrap();
    assert!(out.status.success());
    // CLI-паритет с Go-эталоном (recorded version): бинарь печатает
    // sing-box-совместимую версию (7f-3c-4c)
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("sing-box version"),
        "version должен быть sing-box-паритетным"
    );
}

#[test]
fn missing_listen_socket_exits_2() {
    let out = Command::new(bin()).arg("serve").output().unwrap();
    assert_eq!(out.status.code(), Some(2));
}
