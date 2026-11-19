// SPDX-License-Identifier: GPL-3.0-only

//! Бинарь ядра LAVRay (волна 7g, MVP): `serve --listen-socket <addr>
//! [--data <dir>]` — паритет протокола запуска Go-ядра (docs/stage3
//! shell-lifecycle §3): токен — первой строкой stdin, готовность —
//! строкой LAVRAY_CORE_READY в stdout. Named pipe Windows и полный
//! lifecycle-интерсептор — следующие подволнны (ROADMAP 7g).

mod listener;
mod ruleset;
mod serve;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("serve") => {
            let code = serve::run(&args[2..]);
            std::process::exit(code);
        }
        Some("rule-set") => {
            let code = match args.get(2).map(String::as_str) {
                Some("match") => ruleset::run_match(&args[3..]),
                _ => {
                    eprintln!(
                        "использование: lavray-core rule-set match <path> <домен|IP> [-f source]"
                    );
                    2
                }
            };
            std::process::exit(code);
        }
        Some("version" | "--version") => {
            println!("lavray-core {}", env!("CARGO_PKG_VERSION"));
        }
        _ => {
            eprintln!(
                "использование: lavray-core serve --listen-socket <unix://…|127.0.0.1:0> [--data <dir>]\n\
                 \x20              lavray-core rule-set match <path> <домен|IP> [-f source]\n\
                 \x20              lavray-core version"
            );
            std::process::exit(2);
        }
    }
}
