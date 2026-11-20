// SPDX-License-Identifier: GPL-3.0-only

//! Выбор outbound'а serve: активный профиль из store (настройка
//! `outbound.profile_id`) → outbound движка; fallback Direct.

use lavray_store::Store;
use std::sync::Arc;

/// Имя outbound'а для лога запуска.
#[must_use]
pub fn name(o: &lavray_engine::Outbound) -> &'static str {
    match o {
        lavray_engine::Outbound::Direct => "direct",
        lavray_engine::Outbound::Shadowsocks(_) => "shadowsocks",
        lavray_engine::Outbound::Trojan(_) => "trojan",
        lavray_engine::Outbound::Vmess(_) => "vmess",
        lavray_engine::Outbound::Vless(_) => "vless",
        lavray_engine::Outbound::Hy2(_) => "hysteria2",
        lavray_engine::Outbound::Tuic(_) => "tuic",
    }
}

/// Активный профиль → outbound движка; без профиля/неподдержанного
/// типа — Direct (7g MVP fallback).
#[must_use]
pub fn active_outbound(store: &Arc<std::sync::Mutex<Store>>) -> lavray_engine::Outbound {
    use lavray_engine::profile_outbound::{ProfileOutbound, from_profile};
    let st = store
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(id) = st
        .get_setting("outbound.profile_id")
        .ok()
        .flatten()
        .and_then(|v| v.as_i64())
    else {
        return lavray_engine::Outbound::Direct;
    };
    let Ok(p) = st.get_profile(id) else {
        return lavray_engine::Outbound::Direct;
    };
    match from_profile(&p) {
        Ok(ProfileOutbound::Vless(v)) => lavray_engine::Outbound::Vless(Box::new(v)),
        Ok(ProfileOutbound::Hysteria2(h)) => lavray_engine::Outbound::Hy2(h),
        Ok(ProfileOutbound::Tuic(t)) => lavray_engine::Outbound::Tuic(t),
        _ => lavray_engine::Outbound::Direct,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_profile_falls_back_to_direct() {
        let store = Arc::new(std::sync::Mutex::new(Store::open_memory().expect("store")));
        assert!(matches!(
            active_outbound(&store),
            lavray_engine::Outbound::Direct
        ));
    }

    #[test]
    fn hy2_profile_selected() {
        let store = Arc::new(std::sync::Mutex::new(Store::open_memory().expect("store")));
        let st = store
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let p: lavray_model::profile::Profile =
            serde_json::from_str(r#"{"type":"hysteria2","name":"h","address":"1.2.3.4","port":443,"detail":{"password":"p"}}"#)
                .expect("profile");
        let id = st.create_profile(&p).expect("create");
        st.set_setting("outbound.profile_id", &serde_json::json!(id))
            .expect("setting");
        drop(st);
        assert!(matches!(
            active_outbound(&store),
            lavray_engine::Outbound::Hy2(_)
        ));
    }
}
