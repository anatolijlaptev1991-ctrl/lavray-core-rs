// SPDX-License-Identifier: GPL-3.0-only

//! Декодирование профиля из одной строки выборки (порт Go `store/profiles.go`
//! scanProfile): канонический JSON (profiles.data) + синхронизация поисковых
//! полей из колонок (источник истины для них — SQL). Вынесено ради трещотки.

use lavray_model::{Profile, TestResult, TrafficCounters};

/// Декодировать профиль из строки (порядок колонок PROFILE_COLS).
pub(crate) fn scan_profile(r: &rusqlite::Row<'_>) -> rusqlite::Result<Profile> {
    let id: i64 = r.get(0)?;
    let group_id: i64 = r.get(1)?;
    let favorite: i64 = r.get(2)?;
    let notes: Option<String> = r.get(3)?;
    let latency: Option<i64> = r.get(4)?;
    let full_report: Option<String> = r.get(5)?;
    let tested_at: Option<i64> = r.get(6)?;
    let uplink: i64 = r.get(7)?;
    let downlink: i64 = r.get(8)?;
    let custom_hash: Option<String> = r.get(9)?;
    let created_at: i64 = r.get(10)?;
    let updated_at: i64 = r.get(11)?;
    let data: String = r.get(12)?;

    let mut p: Profile = serde_json::from_str(&data)
        .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
    p.id = id;
    p.group_id = group_id;
    p.favorite = favorite != 0;
    p.notes = notes.unwrap_or_default();
    p.test_result = TestResult {
        latency_ms: latency.and_then(|v| i32::try_from(v).ok()),
        full_report: full_report.unwrap_or_default(),
        tested_at_ms: tested_at,
        last_error: p.test_result.last_error,
    };
    p.traffic = TrafficCounters {
        uplink_bytes: uplink,
        downlink_bytes: downlink,
    };
    p.custom_hash = custom_hash.unwrap_or_default();
    p.created_at_ms = created_at;
    p.updated_at_ms = updated_at;
    Ok(p)
}
