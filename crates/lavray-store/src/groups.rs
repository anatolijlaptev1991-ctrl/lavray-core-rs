// SPDX-License-Identifier: GPL-3.0-only

//! Группы: полная персистенция всех полей (паритет Go `store/groups.go`),
//! nextID с высоководной отметкой (L18: id удалённых не переиспользуются),
//! вычисленный ProfileOrder. Вынесено из lib.rs ради трещотки размеров.

use crate::group_scan::{null_ms, null_str, scan_group};
use crate::helpers::{kind_to_i64, now_ms};
use crate::{Result, Store, StoreError};
use lavray_model::Group;
use rusqlite::{params, OptionalExtension};

const GROUP_COLS: &str = "id, kind, name, subscription_url, archive, skip_auto_update, \
     front_proxy_id, subscription_info, update_interval_min, user_agent, http_headers, \
     http_basic_user, last_working_url, last_update_ms, tab_order, ui_state, created_at_ms, updated_at_ms";

impl Store {
    /// Создать группу (id и tab_order назначаются, если 0). Вернуть id.
    pub fn create_group(&self, g: &Group) -> Result<i64> {
        if g.name.is_empty() {
            return Err(StoreError::Model("store: group name is required".into()));
        }
        let id = if g.id == 0 {
            self.next_id("groups")?
        } else {
            g.id
        };
        let tab_order = if g.tab_order == 0 {
            let max: i64 =
                self.conn
                    .query_row("SELECT COALESCE(MAX(tab_order), 0) FROM groups", [], |r| {
                        r.get(0)
                    })?;
            max + 1
        } else {
            g.tab_order
        };
        let now = now_ms();
        let created = if g.created_at_ms == 0 {
            now
        } else {
            g.created_at_ms
        };
        let sub_info = g
            .subscription_info
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(|e| StoreError::Model(e.to_string()))?;
        let headers = if g.http_headers.is_empty() {
            None
        } else {
            Some(
                serde_json::to_string(&g.http_headers)
                    .map_err(|e| StoreError::Model(e.to_string()))?,
            )
        };
        self.conn.execute(
            "INSERT INTO groups (id, kind, name, subscription_url, archive, skip_auto_update, \
             front_proxy_id, subscription_info, update_interval_min, user_agent, http_headers, \
             http_basic_user, last_working_url, last_update_ms, tab_order, ui_state, created_at_ms, updated_at_ms) \
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18)",
            params![
                id,
                kind_to_i64(g.kind),
                g.name,
                null_str(&g.subscription_url),
                i64::from(g.archive),
                i64::from(g.skip_auto_update),
                g.front_proxy_id,
                sub_info,
                g.update_interval_min,
                null_str(&g.user_agent),
                headers,
                null_str(&g.http_basic_user),
                null_str(&g.last_working_url),
                null_ms(g.last_update_ms),
                tab_order,
                null_str(&g.ui_state),
                created,
                now,
            ],
        )?;
        Ok(id)
    }

    /// Группа по id с вычисленным ProfileOrder.
    pub fn get_group(&self, id: i64) -> Result<Group> {
        let sql = format!("SELECT {GROUP_COLS} FROM groups WHERE id = ?1");
        let mut g = self
            .conn
            .query_row(&sql, [id], scan_group)
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => {
                    StoreError::NotFound(format!("группа {id}"))
                }
                other => StoreError::Sqlite(other),
            })?;
        self.load_profile_order(&mut g)?;
        Ok(g)
    }

    /// Все группы в порядке вкладок (FR-UI-113).
    pub fn list_groups(&self) -> Result<Vec<Group>> {
        let sql = format!("SELECT {GROUP_COLS} FROM groups ORDER BY tab_order, id");
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map([], scan_group)?;
        let mut out = Vec::new();
        for r in rows {
            let mut g = r?;
            self.load_profile_order(&mut g)?;
            out.push(g);
        }
        Ok(out)
    }

    /// Удалить группу (каскад профилей). Последнюю группу удалить нельзя (FR-UI-107).
    pub fn delete_group(&self, id: i64) -> Result<()> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM groups", [], |r| r.get(0))?;
        if count <= 1 {
            return Err(StoreError::Model(
                "store: нельзя удалить последнюю группу".into(),
            ));
        }
        let n = self
            .conn
            .execute("DELETE FROM groups WHERE id = ?1", [id])?;
        if n == 0 {
            return Err(StoreError::NotFound(format!("группа {id}")));
        }
        Ok(())
    }

    fn load_profile_order(&self, g: &mut Group) -> Result<()> {
        let mut stmt = self
            .conn
            .prepare("SELECT id FROM profiles WHERE group_id = ?1 ORDER BY sort_key, id")?;
        let rows = stmt.query_map([g.id], |r| r.get::<_, i64>(0))?;
        g.profile_order = rows.collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(())
    }

    /// Следующий id: высоководная отметка в meta только растёт (L18 аудита №1 —
    /// MAX(id)+1 переиспользует id удалённой записи, ломая chain/front_proxy).
    fn next_id(&self, table: &str) -> Result<i64> {
        let key = format!("store.last_id.{table}");
        let max_id: i64 = self.conn.query_row(
            &format!("SELECT COALESCE(MAX(id), 0) FROM {table}"),
            [],
            |r| r.get(0),
        )?;
        let mut next = max_id + 1;
        let saved: Option<String> = self
            .conn
            .query_row("SELECT value FROM meta WHERE key = ?1", [&key], |r| {
                r.get(0)
            })
            .optional()?;
        if let Some(v) = saved.and_then(|s| s.parse::<i64>().ok()) {
            if v >= next {
                next = v + 1;
            }
        }
        self.conn.execute(
            "INSERT INTO meta (key, value) VALUES (?1, ?2) \
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, next.to_string()],
        )?;
        Ok(next)
    }
}
