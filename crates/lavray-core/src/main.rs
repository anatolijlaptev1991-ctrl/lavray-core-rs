// SPDX-License-Identifier: GPL-3.0-only

//! Бинарь ядра LAVRay (волна 7g, MVP): `serve --listen-socket <addr>
//! [--data <dir>]` — паритет протокола запуска Go-ядра (docs/stage3
//! shell-lifecycle §3): токен — первой строкой stdin, готовность —
//! строкой LAVRAY_CORE_READY в stdout. Named pipe Windows и полный
//! lifecycle-интерсептор — следующие подволнны (ROADMAP 7g).

mod cli;
mod cli_help;
mod listener;
mod mcp;
mod mcp_tools;
mod outbound_select;
mod ruleset;
mod serve;
mod serve_modes;
mod updates;

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
        Some("mcp") => {
            std::process::exit(mcp::run(&args[2..]));
        }
        Some("updates") => {
            std::process::exit(updates::run_check(&args[3..]));
        }
        Some("check") => {
            std::process::exit(cli::run_check(&args[2..]));
        }
        Some("format") => {
            std::process::exit(cli::run_format(&args[2..]));
        }
        Some("version" | "--version") => {
            // CLI-паритет: версия печатается как у Go-эталона (recorded)
            println!("{}", cli_help::VERSION_OUTPUT);
        }
        Some("help" | "--help") | None => {
            println!("{}", cli_help::ROOT_HELP);
        }
        Some(other) => {
            // unknown command: cobra Error + подсказка + FATAL, exit 1
            cli_help::unknown_command(other, cli::FATAL);
            std::process::exit(1);
        }
    }
}
