// SPDX-License-Identifier: GPL-3.0-only

//! CLI-паритет с sing-box (дроп-ин): help `rule-set` байт-в-байт с эталоном
//! (recorded trap-033; имя бинаря — часть записанного поведения).

pub(crate) const RULESET_HELP: &str = r#"Manage rule-sets

Usage:
  sing-box rule-set [command]

Available Commands:
  compile     Compile rule-set json to binary
  convert     Convert adguard DNS filter to rule-set
  decompile   Decompile rule-set binary to json
  format      Format rule-set json
  match       Check if an IP address or a domain matches the rule-set
  merge       Merge rule-set source files
  upgrade     Upgrade rule-set json

Flags:
  -h, --help   help for rule-set

Global Flags:
  -c, --config stringArray             set configuration file path
  -C, --config-directory stringArray   set configuration directory path
  -D, --directory string               set working directory
      --disable-color                  disable color output

Use "sing-box rule-set [command] --help" for more information about a command."#;

/// Usage-часть help (без краткого описания) — cobra Error-вывод.
pub(crate) fn ruleset_usage_body() -> &'static str {
    // Префикс «Manage rule-sets\n\n» (18 байт) отбрасывается.
    &RULESET_HELP[18..]
}
