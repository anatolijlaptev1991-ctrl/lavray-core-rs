// SPDX-License-Identifier: GPL-3.0-only

//! Хелперы хранилища: конверсия типов модели в колонки sqlite, время.

use lavray_model::{GroupKind, ProfileType};

/// GroupKind → колонка kind (1 basic | 2 subscription).
pub fn kind_to_i64(k: GroupKind) -> i64 {
    match k {
        GroupKind::Basic => 1,
        GroupKind::Subscription => 2,
    }
}

/// Колонка kind → GroupKind.
pub fn i64_to_kind(v: i64) -> GroupKind {
    if v == 2 {
        GroupKind::Subscription
    } else {
        GroupKind::Basic
    }
}

/// ProfileType → строка колонки type (паритет Go).
pub fn type_str(t: ProfileType) -> &'static str {
    match t {
        ProfileType::Socks => "socks",
        ProfileType::Http => "http",
        ProfileType::Shadowsocks => "shadowsocks",
        ProfileType::Trojan => "trojan",
        ProfileType::VMess => "vmess",
        ProfileType::Vless => "vless",
        ProfileType::Naive => "naive",
        ProfileType::Hysteria2 => "hysteria2",
        ProfileType::Tuic => "tuic",
        ProfileType::CustomOutbound => "custom_outbound",
        ProfileType::CustomConfig => "custom_config",
        ProfileType::CustomExternal => "custom_external",
        ProfileType::Chain => "chain",
    }
}

/// Текущее время в миллисекундах (u128 → i64 безопасно для эпохи).
pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(0))
}
