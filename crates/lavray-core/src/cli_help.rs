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

/// Корневой help cobra (recorded help-root, stdout exit 0).
pub(crate) const ROOT_HELP: &str = r#"Usage:
  sing-box [command]

Available Commands:
  api          API service client
  check        Check configuration
  completion   Generate the autocompletion script for the specified shell
  format       Format configuration
  generate     Generate things
  geoip        GeoIP tools
  geosite      Geosite tools
  help         Help about any command
  merge        Merge configurations
  rule-set     Manage rule-sets
  run          Run service
  schema       Generate configuration JSON schema
  tools        Experimental tools
  version      Print current version of sing-box

Flags:
  -c, --config stringArray             set configuration file path
  -C, --config-directory stringArray   set configuration directory path
  -D, --directory string               set working directory
      --disable-color                  disable color output
  -h, --help                           help for sing-box

Use "sing-box [command] --help" for more information about a command."#;

/// Version-вывод (recorded version, байт-в-байт с Go-эталоном).
pub(crate) const VERSION_OUTPUT: &str = "sing-box version 1.14.1-neko.1

Environment: go1.27.0 windows/amd64
Tags: with_gvisor,with_quic,with_dhcp,with_wireguard,with_utls,with_acme,with_clash_api,with_tailscale,with_ccm,with_ocm,with_cloudflared,with_usbip,with_openvpn,with_openconnect
Revision: 628a9ed70b127e0226fa86b50e5d9a9d14b824bb
CGO: disabled";

/// Cobra unknown command: Error + подсказка в stderr, FATAL-строка следом,
/// exit 1 (recorded unknown-command).
pub(crate) fn unknown_command(cmd: &str, fatal: &str) {
    eprintln!("Error: unknown command \"{cmd}\" for \"sing-box\"");
    eprintln!("Run 'sing-box --help' for usage.");
    eprintln!("{fatal} unknown command \"{cmd}\" for \"sing-box\"");
}
