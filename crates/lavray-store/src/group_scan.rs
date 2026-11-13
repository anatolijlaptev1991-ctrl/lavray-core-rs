// SPDX-License-Identifier: GPL-3.0-only

//! Скан строки группы и nullable-хелперы (паритет Go `store/groups.go`
//! scanGroup/nullableString/nullableMs). Вынесено из groups.rs ради трещотки.

use crate::helpers::i64_to_kind;
use lavray_model::{Group, SubscriptionInfo};
use std::collections::BTreeMap;

/// Полная колонка группы → Group (18 полей, порядок GROUP_COLS).
pub(crate) fn scan_group(r: &rusqlite::Row<'_>) -> rusqlite::Result<Group> {
    let sub_info: Option<String> = r.get(7)?;
    let headers: Option<String> = r.get(10)?;
    Ok(Group {
        id: r.get(0)?,
        kind: i64_to_kind(r.get(1)?),
        name: r.get(2)?,
        subscription_url: r.get::<_, Option<String>>(3)?.unwrap_or_default(),
        archive: r.get::<_, i64>(4)? != 0,
        skip_auto_update: r.get::<_, i64>(5)? != 0,
        front_proxy_id: r.get(6)?,
        subscription_info: sub_info
            .filter(|s| !s.is_empty())
            .and_then(|s| serde_json::from_str::<SubscriptionInfo>(&s).ok()),
        update_interval_min: r.get(8)?,
        user_agent: r.get::<_, Option<String>>(9)?.unwrap_or_default(),
        http_headers: headers
            .filter(|s| !s.is_empty())
            .and_then(|s| serde_json::from_str::<BTreeMap<String, String>>(&s).ok())
            .unwrap_or_default(),
        http_basic_user: r.get::<_, Option<String>>(11)?.unwrap_or_default(),
        last_working_url: r.get::<_, Option<String>>(12)?.unwrap_or_default(),
        last_update_ms: r.get::<_, Option<i64>>(13)?.unwrap_or(0),
        tab_order: r.get(14)?,
        ui_state: r.get::<_, Option<String>>(15)?.unwrap_or_default(),
        created_at_ms: r.get(16)?,
        updated_at_ms: r.get(17)?,
        profile_order: Vec::new(),
    })
}

/// Пустая строка → NULL (паритет Go nullableString).
pub(crate) fn null_str(s: &str) -> Option<&str> {
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

/// 0 мс → NULL («никогда», паритет Go nullableMs).
pub(crate) fn null_ms(ms: i64) -> Option<i64> {
    if ms == 0 {
        None
    } else {
        Some(ms)
    }
}
