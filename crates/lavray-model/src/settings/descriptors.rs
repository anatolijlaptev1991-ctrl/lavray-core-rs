// SPDX-License-Identifier: GPL-3.0-only

//! Базовый каталог ключей LAVRay (порт Go `model/settings.go` baseDescriptors,
//! Приложение А REQUIREMENTS + миграция core-port-plan §5.4).
//! extraCore.core_map NekoBox НЕ переносится (DROP, FR-UI-175).

use super::{SettingDescriptor, SettingType, SETTING_HWID_ID};
use SettingType::{Bool, Int, String as Str, StringList};

/// Базовые дескрипторы настроек.
#[allow(clippy::too_many_lines)] // каталог-таблица данных, верный порт Go baseDescriptors
pub fn base_descriptors() -> Vec<SettingDescriptor> {
    vec![
        // ---- Inbound (FR-UI-157/158/279) ----
        SettingDescriptor::new("inbound.address", Str, "inbound")
            .def("\"127.0.0.1\"")
            .restart()
            .dep("inbound_address"),
        SettingDescriptor::new("inbound.port", Int, "inbound")
            .def("2080")
            .restart()
            .dep("inbound_socks_port"),
        SettingDescriptor::new("inbound.auth.user", Str, "inbound")
            .restart()
            .dep("inbound_auth.user"),
        SettingDescriptor::new("inbound.auth.pass", Str, "inbound")
            .restart()
            .dep("inbound_auth.pass"),
        SettingDescriptor::new("inbound.custom_inbound", Str, "inbound")
            .restart()
            .dep("custom_inbound"),
        // ---- Тесты (URL- и полный тест, T-84) ----
        SettingDescriptor::new("test.url", Str, "test")
            .def("\"https://www.gstatic.com/generate_204\"")
            .dep("test_url"),
        SettingDescriptor::new("test.url_dl", Str, "test")
            .def("\"http://cachefly.cachefly.net/10mb.test\"")
            .dep("test_url_dl"),
        SettingDescriptor::new("test.dl_timeout", Int, "test")
            .def("10")
            .dep("test_dl_timeout"),
        SettingDescriptor::new("test.concurrent", Int, "test")
            .def("5")
            .dep("test_concurrent"),
        SettingDescriptor::new("test.url_ip", Str, "test")
            .def("\"https://cloudflare.com/cdn-cgi/trace\""),
        SettingDescriptor::new("test.udp_target", Str, "test").def("\"1.1.1.1:53\""),
        // ---- Маршрутизация ----
        SettingDescriptor::new("routing.active_preset", Str, "routing")
            .def("\"lav-ru\"")
            .restart()
            .dep("active_routing"),
        SettingDescriptor::new("routing.custom_global", Str, "routing")
            .restart()
            .dep("custom_route"),
        // ---- Подписки (LNB-33: use_proxy default true) ----
        SettingDescriptor::new("sub.user_agent", Str, "sub").dep("user_agent2"),
        SettingDescriptor::new("sub.use_proxy", Bool, "sub")
            .def("true")
            .dep("sub_use_proxy"),
        SettingDescriptor::new("sub.clear", Bool, "sub").dep("sub_clear"),
        SettingDescriptor::new("sub.insecure", Bool, "sub").dep("sub_insecure"),
        SettingDescriptor::new("sub.auto_update", Int, "sub")
            .def("0")
            .dep("sub_auto_update"),
        SettingDescriptor::new("sub.hwid_enabled", Bool, "sub").def("false"),
        SettingDescriptor {
            internal: true,
            ..SettingDescriptor::new(SETTING_HWID_ID, Str, "sub")
        },
        // ---- Запоминание ----
        SettingDescriptor::new("remember.id", Int, "remember")
            .def("-1")
            .dep("remember_id"),
        SettingDescriptor::new("remember.enable", Bool, "remember").dep("remember_enable"),
        SettingDescriptor::new("remember.modes", StringList, "remember").dep("spmode2"),
        // ---- UI (shell_owned; conn_stat всегда true — FR-UI-274) ----
        SettingDescriptor::new("ui.theme", Str, "ui")
            .shell()
            .dep("theme"),
        SettingDescriptor::new("ui.lang", Str, "ui")
            .shell()
            .dep("language"),
        SettingDescriptor::new("ui.window_size", Str, "ui")
            .shell()
            .dep("mw_size"),
        SettingDescriptor::new("ui.splitter", Str, "ui")
            .shell()
            .dep("splitter_state"),
        SettingDescriptor::new("ui.start_minimal", Bool, "ui")
            .shell()
            .dep("start_minimal"),
        SettingDescriptor::new("ui.max_log_lines", Int, "ui")
            .shell()
            .def("1000")
            .dep("max_log_line"),
        SettingDescriptor::new("ui.conn_stat", Bool, "ui")
            .def("true")
            .dep("conn_stat"),
        SettingDescriptor::new("ui.log_ignore", StringList, "ui")
            .shell()
            .dep("log_ignore"),
        SettingDescriptor::new("ui.current_group", Int, "ui")
            .shell()
            .dep("current_group"),
        // ---- TUN (+tun.kill_switch FR-UI-275, +tun.interface_name) ----
        SettingDescriptor::new("tun.fake_dns", Bool, "tun").dep("fakedns"),
        SettingDescriptor::new("tun.enabled", Bool, "tun").dep("vpn_internal_tun"),
        SettingDescriptor::new("tun.impl", Int, "tun").dep("vpn_impl"),
        SettingDescriptor::new("tun.mtu", Int, "tun")
            .def("9000")
            .dep("vpn_mtu"),
        SettingDescriptor::new("tun.ipv6", Bool, "tun").dep("vpn_ipv6"),
        SettingDescriptor::new("tun.hide_console", Bool, "tun")
            .shell()
            .dep("vpn_hide_console"),
        SettingDescriptor::new("tun.strict_route", Bool, "tun").dep("vpn_strict_route"),
        SettingDescriptor::new("tun.bypass_process", Str, "tun").dep("vpn_bypass_process"),
        SettingDescriptor::new("tun.bypass_cidr", Str, "tun").dep("vpn_bypass_cidr"),
        SettingDescriptor::new("tun.whitelist", Bool, "tun").dep("vpn_rule_white"),
        SettingDescriptor::new("tun.kill_switch", Bool, "tun").def("false"),
        SettingDescriptor::new("tun.interface_name", Str, "tun").def("\"lavray-tun\""),
        // ---- Хоткеи (shell_owned) ----
        SettingDescriptor::new("hotkeys.main_window", Str, "hotkeys")
            .shell()
            .dep("hk_mw"),
        SettingDescriptor::new("hotkeys.group", Str, "hotkeys")
            .shell()
            .dep("hk_group"),
        SettingDescriptor::new("hotkeys.routing", Str, "hotkeys")
            .shell()
            .dep("hk_route"),
        SettingDescriptor::new("hotkeys.system_proxy_menu", Str, "hotkeys")
            .shell()
            .dep("hk_spmenu"),
        // ---- Ядро (clash_api hardening — core-port-plan §6.3) ----
        SettingDescriptor::new("core.clash_api.enabled", Bool, "core").dep("core_box_clash_api"),
        SettingDescriptor::new("core.clash_api.secret", Str, "core")
            .dep("core_box_clash_api_secret"),
        SettingDescriptor::new("core.underlying_dns", Str, "core")
            .def("\"local\"")
            .dep("core_box_underlying_dns"),
        SettingDescriptor::new("log.level", Str, "core")
            .def("\"info\"")
            .restart()
            .dep("log_level"),
        SettingDescriptor::new("connect.health_check", Bool, "core").def("true"),
        SettingDescriptor::new("connect.kill_switch_proxy", Bool, "core")
            .shell()
            .def("false"),
        // ---- Безопасность ----
        SettingDescriptor::new("security.allow_insecure_default", Bool, "security")
            .dep("skip_cert"),
        SettingDescriptor::new("security.utls_fingerprint", Str, "security").dep("utlsFingerprint"),
        // ---- Mux ----
        SettingDescriptor::new("mux.protocol", Str, "mux")
            .def("\"h2mux\"")
            .dep("mux_protocol"),
        SettingDescriptor::new("mux.concurrency", Int, "mux")
            .def("-1")
            .dep("mux_concurrency"),
        SettingDescriptor::new("mux.padding", Bool, "mux").dep("mux_padding"),
        SettingDescriptor::new("mux.default_on", Bool, "mux").dep("mux_default_on"),
        // ---- Агенты (MCP): off | read | control ----
        SettingDescriptor::new("agent.mode", Str, "agent").def("\"off\""),
        // ---- Прочее ----
        SettingDescriptor::new("win.sp_format", Str, "misc")
            .shell()
            .dep("sp_format"),
        SettingDescriptor::new("update.channel", Str, "update")
            .def("\"stable\"")
            .dep("check_include_pre"),
        SettingDescriptor::new("update.auto_check", Bool, "update").def("true"),
        SettingDescriptor::new("stats.interval_ms", Int, "misc")
            .def("1000")
            .dep("traffic_loop_interval"),
        SettingDescriptor::new("share.vmess_old_format", Bool, "misc")
            .def("true")
            .dep("old_share_link_format"),
        SettingDescriptor::new("enable_external_cores", Bool, "core").def("false"),
        SettingDescriptor::new("web.bind", Str, "core"),
        SettingDescriptor::new("web.tls", Bool, "core").def("false"),
    ]
}
