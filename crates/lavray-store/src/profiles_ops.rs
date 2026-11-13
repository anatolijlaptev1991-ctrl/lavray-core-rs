// SPDX-License-Identifier: GPL-3.0-only

//! Профили: чтение и точечные операции (порт Go `store/profiles.go`
//! SaveTestResult/SaveTraffic/Get/List/Delete/Reorder). Вынесено из profiles.rs
//! ради трещотки размеров.

use crate::profile_scan::scan_profile;
use crate::profiles::{null_str, PROFILE_COLS, SORT_KEY_STEP};
use crate::{Result, Store, StoreError};
use lavray_model::{Profile, TestResult, TrafficCounters};
use rusqlite::params;

impl Store {
    /// Записать результат теста отдельным UPDATE (T-22): остальные поля не
    /// трогаются, updated_at_ms не меняется. Пустой результат очищает прежний.
    pub fn save_test_result(&self, id: i64, r: &TestResult) -> Result<()> {
        let blob = serde_json::to_string(r).map_err(|e| StoreError::Model(e.to_string()))?;
        let n = self.conn.execute(
            "UPDATE profiles SET latency_ms=?1, tested_at_ms=?2, full_report=?3, \
             data = json_set(data, '$.test_result', json(?4)) WHERE id=?5",
            params![
                r.latency_ms.map(i64::from),
                r.tested_at_ms,
                null_str(&r.full_report),
                blob,
                id
            ],
        )?;
        if n == 0 {
            return Err(StoreError::NotFound(format!("профиль {id}")));
        }
        Ok(())
    }

    /// Записать счётчики трафика отдельным UPDATE (D-04): UpdateProfile их не пишет.
    pub fn save_traffic(&self, id: i64, t: &TrafficCounters) -> Result<()> {
        let blob = serde_json::to_string(t).map_err(|e| StoreError::Model(e.to_string()))?;
        let n = self.conn.execute(
            "UPDATE profiles SET uplink_total=?1, downlink_total=?2, \
             data = json_set(data, '$.traffic', json(?3)) WHERE id=?4",
            params![t.uplink_bytes, t.downlink_bytes, blob, id],
        )?;
        if n == 0 {
            return Err(StoreError::NotFound(format!("профиль {id}")));
        }
        Ok(())
    }

    /// Профиль по id (канонический JSON + синхронизация поисковых полей из колонок).
    pub fn get_profile(&self, id: i64) -> Result<Profile> {
        let sql = format!("SELECT {PROFILE_COLS} FROM profiles WHERE id = ?1");
        self.conn
            .query_row(&sql, [id], scan_profile)
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => {
                    StoreError::NotFound(format!("профиль {id}"))
                }
                other => StoreError::Sqlite(other),
            })
    }

    /// Профили группы в каноническом порядке; group_id < 0 — все профили.
    /// 0 — валидный id группы (каталог NekoBox), «все» — отрицательное значение.
    pub fn list_profiles(&self, group_id: i64) -> Result<Vec<Profile>> {
        let mut sql = format!("SELECT {PROFILE_COLS} FROM profiles");
        if group_id >= 0 {
            sql.push_str(" WHERE group_id = ?1");
        }
        sql.push_str(" ORDER BY group_id, sort_key, id");
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = if group_id >= 0 {
            stmt.query_map([group_id], scan_profile)?
        } else {
            stmt.query_map([], scan_profile)?
        };
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    /// Удалить профиль (запуск запущенного проверяет слой API, FR-UI-038).
    pub fn delete_profile(&self, id: i64) -> Result<()> {
        let n = self
            .conn
            .execute("DELETE FROM profiles WHERE id = ?1", [id])?;
        if n == 0 {
            return Err(StoreError::NotFound(format!("профиль {id}")));
        }
        Ok(())
    }

    /// Число профилей в группе.
    pub fn count_profiles(&self, group_id: i64) -> Result<i64> {
        self.conn
            .query_row(
                "SELECT COUNT(*) FROM profiles WHERE group_id = ?1",
                [group_id],
                |r| r.get(0),
            )
            .map_err(Into::into)
    }

    /// Порядок профилей в группе (FR-UI-074): перечисленные id получают порядок
    /// перечисления; неперечисленные добавляются в конец в текущем порядке.
    pub fn reorder_profiles(&self, group_id: i64, ordered_ids: &[i64]) -> Result<()> {
        let in_group: Vec<i64> = {
            let mut stmt = self
                .conn
                .prepare("SELECT id FROM profiles WHERE group_id = ?1")?;
            let rows = stmt.query_map([group_id], |r| r.get(0))?;
            rows.collect::<rusqlite::Result<Vec<_>>>()?
        };
        let mut next = 0i64;
        let mut listed: Vec<i64> = Vec::new();
        for &id in ordered_ids {
            if !in_group.contains(&id) || listed.contains(&id) {
                continue;
            }
            listed.push(id);
            next += SORT_KEY_STEP;
            self.conn.execute(
                "UPDATE profiles SET sort_key = ?1 WHERE id = ?2",
                params![next, id],
            )?;
        }
        let rest: Vec<i64> = {
            let mut stmt = self
                .conn
                .prepare("SELECT id FROM profiles WHERE group_id = ?1 ORDER BY sort_key, id")?;
            let rows = stmt.query_map([group_id], |r| r.get(0))?;
            rows.collect::<rusqlite::Result<Vec<_>>>()?
        };
        for id in rest {
            if listed.contains(&id) {
                continue;
            }
            next += SORT_KEY_STEP;
            self.conn.execute(
                "UPDATE profiles SET sort_key = ?1 WHERE id = ?2",
                params![next, id],
            )?;
        }
        Ok(())
    }
}
