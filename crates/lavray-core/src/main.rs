// SPDX-License-Identifier: GPL-3.0-only

//! Бинарь ядра LAVRay (волна 7g, MVP): `serve --listen-socket <addr>
//! [--data <dir>]` — паритет протокола запуска Go-ядра (docs/stage3
//! shell-lifecycle §3): токен — первой строкой stdin, готовность —
//! строкой LAVRAY_CORE_READY в stdout. Named pipe Windows и полный
//! lifecycle-интерсептор — следующие подволнны (ROADMAP 7g).

mod cli;
mod cli_help;
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
                Some("format") => ruleset::run_format(&args[3..]),
                Some("compile") => ruleset::run_compile(&args[3..]),
                _ => {
                    // CLI-паритет cobra: неизвестный флаг — Error+usage+FATAL
                    // (exit 1); иначе help группы в stdout, exit 0.
                    if let Some(flag) = cli::first_unknown_group_flag(&args[3..]) {
                        cli::ruleset_unknown_flag(&flag);
                        1
                    } else {
                        println!("{}", cli::RULESET_HELP);
                        0
                    }
                }
            };
            std::process::exit(code);
        }
        Some("check") => {
            std::process::exit(cli::run_check(&args[2..]));
        }
        Some("format") => {
            std::process::exit(cli::run_format(&args[2..]));
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
