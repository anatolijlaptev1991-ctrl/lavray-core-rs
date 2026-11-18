// SPDX-License-Identifier: GPL-3.0-only

//! Таблица «ключ → читатель», разбитая по темам (вынесено из readers.rs
//! трещоткой размеров и clippy too_many_lines: каждой теме — своя функция
//! до 100 строк).

use super::SETTING_HWID_ID;
use super::readers::{SettingReader, api, import_only, shell, ui};
/// Общие причины import-only (паритет Go settings_readers.go).
const HOTKEYS: &str = "сочетание «подключить / отключить» хранится в ui-state.json (lavray.hotkeyConnect); ключи NekoBox не читаются";
const CLASH_API: &str =
    "clash_api в конфиге запрещён (core-port-plan §6.3, hardening), настройка не используется";
const UI_STATE: &str = "хранится и читается интерфейсом под своим именем (localStorage и ui-state.json, ключи lavray.*), ключ ядра не используется";

use super::update::{
    SETTING_UPDATE_LAST_CHECKED, SETTING_UPDATE_LAST_URL, SETTING_UPDATE_ROOT_JSON,
    SETTING_UPDATE_ROOT_VERSION, SETTING_UPDATE_SERIAL_BETA, SETTING_UPDATE_SERIAL_STABLE,
    SETTING_UPDATE_TIMESTAMP_VERSION,
};

/// Сеть и режим: инбаунд, тесты, маршрутизация, подписки, автозапуск, TUN.
pub(super) fn reader_tables_net() -> Vec<(&'static str, SettingReader)> {
    vec![
        ("inbound.address", api("server.go")),
        ("inbound.port", api("server.go")),
        ("inbound.auth.user", api("server.go")),
        ("inbound.auth.pass", api("server.go")),
        ("inbound.custom_inbound", api("server.go")),
        ("test.url", api("test_instance.go")),
        ("test.url_dl", api("test_instance.go")),
        ("test.dl_timeout", api("test_instance.go")),
        ("test.concurrent", api("test_instance.go")),
        ("test.url_ip", api("test_instance.go")),
        ("test.udp_target", api("test_instance.go")),
        ("routing.active_preset", api("server.go")),
        ("routing.custom_global", api("server.go")),
        ("sub.user_agent", api("subscription_service.go")),
        ("sub.use_proxy", api("tunnel_http.go")),
        ("sub.clear", api("subscription_service.go")),
        ("sub.insecure", api("subscription_service.go")),
        ("sub.auto_update", api("subscription_auto.go")),
        ("sub.hwid_enabled", api("subscription_service.go")),
        ("remember.id", api("headless_glue.go")),
        ("remember.enable", api("headless_glue.go")),
        ("remember.modes", api("remember.go")),
        ("tun.fake_dns", api("server.go")),
        (
            "tun.enabled",
            import_only("TUN включается режимом Connect, а не настройкой (L21 аудита №1)"),
        ),
        ("tun.impl", api("server.go")),
        ("tun.mtu", api("server.go")),
        ("tun.ipv6", api("server.go")),
        (
            "tun.hide_console",
            import_only("оболочка запускает ядро без окна консоли всегда (CREATE_NO_WINDOW)"),
        ),
        ("tun.strict_route", api("server.go")),
        ("tun.bypass_process", api("server.go")),
        ("tun.bypass_cidr", api("server.go")),
        ("tun.whitelist", api("server.go")),
        ("tun.kill_switch", api("server.go")),
        ("tun.interface_name", api("server.go")),
    ]
}
/// Интерфейс: темы, окно, журнал, горячие клавиши.
pub(super) fn reader_tables_ui() -> Vec<(&'static str, SettingReader)> {
    vec![
        ("ui.theme", import_only(UI_STATE)),
        ("ui.lang", import_only(UI_STATE)),
        (
            "ui.window_size",
            import_only("размер окна хранит плагин window-state оболочки, не карта настроек"),
        ),
        ("ui.splitter", import_only(UI_STATE)),
        (
            "ui.start_minimal",
            import_only(
                "оболочка читает собственный lavray.startMinimized из ui-state.json (shell/src/prefs.rs)",
            ),
        ),
        ("ui.max_log_lines", ui("screens/log/useLogBuffer.ts")),
        (
            "ui.conn_stat",
            import_only("счётчики трафика показываются всегда (FR-UI-274), выключателя нет"),
        ),
        (
            "ui.log_ignore",
            import_only("фильтр строк журнала не реализован, ключ перенесён из NekoBox"),
        ),
        ("ui.current_group", import_only(UI_STATE)),
        ("hotkeys.main_window", import_only(HOTKEYS)),
        ("hotkeys.group", import_only(HOTKEYS)),
        ("hotkeys.routing", import_only(HOTKEYS)),
        ("hotkeys.system_proxy_menu", import_only(HOTKEYS)),
    ]
}
/// Прочее: ядро, соединение, безопасность, mux, обновления, панель.
pub(super) fn reader_tables_misc() -> Vec<(&'static str, SettingReader)> {
    vec![
        (SETTING_HWID_ID, api("subscription_hwid.go")),
        ("core.clash_api.enabled", import_only(CLASH_API)),
        ("core.clash_api.secret", import_only(CLASH_API)),
        ("core.underlying_dns", api("server.go")),
        ("log.level", api("server.go")),
        ("connect.health_check", api("connect_health.go")),
        (
            "connect.kill_switch_proxy",
            shell("shell/src/killswitch.rs"),
        ),
        ("security.allow_insecure_default", api("server.go")),
        (
            "security.utls_fingerprint",
            import_only(
                "отпечаток uTLS берётся из параметров транспорта профиля (Stream.UTLSFingerprint), глобальный ключ не читается",
            ),
        ),
        ("mux.protocol", api("server.go")),
        ("mux.concurrency", api("server.go")),
        ("mux.padding", api("server.go")),
        ("mux.default_on", api("server.go")),
        ("agent.mode", api("agent.go")),
        (
            "win.sp_format",
            import_only(
                "ProxyServer системного прокси всегда host:port; передача формата через UI, set_system_proxy и Backend::apply — отдельная работа (хвосты B)",
            ),
        ),
        ("update.channel", ui("hooks/useUpdateSettings.ts")),
        ("update.auto_check", ui("hooks/useUpdateSettings.ts")),
        (SETTING_UPDATE_ROOT_VERSION, api("update_store.go")),
        (SETTING_UPDATE_TIMESTAMP_VERSION, api("update_store.go")),
        (SETTING_UPDATE_SERIAL_STABLE, api("update_store.go")),
        (SETTING_UPDATE_SERIAL_BETA, api("update_store.go")),
        (SETTING_UPDATE_LAST_CHECKED, api("update_store.go")),
        (SETTING_UPDATE_LAST_URL, api("update_store.go")),
        (
            SETTING_UPDATE_ROOT_JSON,
            import_only(
                "устарел: принятые корни доверия лежат файлами updates/roots и перепроверяются от вшитого корня; ключ остаётся служебным, чтобы SetSettings его не принимал",
            ),
        ),
        ("stats.interval_ms", api("stats_interval.go")),
        ("share.vmess_old_format", api("share_options.go")),
        ("enable_external_cores", api("core_service.go")),
        (
            "web.bind",
            import_only(
                "зарезервирован для веб-панели (Ф7, T-76): адрес пока задают флаги запуска",
            ),
        ),
        (
            "web.tls",
            import_only("зарезервирован для веб-панели (Ф7, T-76): TLS пока задают флаги запуска"),
        ),
    ]
}
