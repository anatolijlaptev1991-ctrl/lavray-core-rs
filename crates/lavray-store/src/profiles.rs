// SPDX-License-Identifier: GPL-3.0-only

//! Профили: полный CRUD (порт Go `store/profiles.go`). Колонки — поисковые/
//! метаданные-копии; канонический JSON всей модели хранится в profiles.data
//! (core-port-plan §5.2). Вынесено из lib.rs ради трещотки размеров.

use crate::helpers::{now_ms, type_str};
use crate::{Result, Store, StoreError};
use lavray_model::Profile;
use rusqlite::params;

/// Шаг sort_key для вставки со сдвигом (§5.2).
pub(crate) const SORT_KEY_STEP: i64 = 1024;

pub(crate) const PROFILE_COLS: &str = "id, group_id, favorite, notes, latency_ms, full_report, \
     tested_at_ms, uplink_total, downlink_total, custom_hash, created_at_ms, updated_at_ms, data";

impl Store {
    /// Создать профиль: id и sort_key назначаются, группа проверяется. Вернуть id.
    /// T-08B: новый профиль не подтверждён (custom_hash сбрасывается).
    pub fn create_profile(&self, p: &Profile) -> Result<i64> {
        let mut p = p.clone();
        p.custom_hash = String::new();
        self.create_profile_inner(&mut p, true)
    }

    /// Сохранить профиль с СОХРАНЁННЫМ id (импортёр NekoBox, §5.3): id каталога
    /// служат ссылками (gid, chain-списки, front_proxy), переназначать нельзя.
    pub fn import_profile(&self, p: &Profile) -> Result<i64> {
        let mut p = p.clone();
        self.create_profile_inner(&mut p, false)
    }

    fn create_profile_inner(&self, p: &mut Profile, auto_id: bool) -> Result<i64> {
        if auto_id && p.id == 0 {
            p.id = self.next_id("profiles")?;
        }
        let exists: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM groups WHERE id = ?1",
            [p.group_id],
            |r| r.get(0),
        )?;
        if exists == 0 {
            return Err(StoreError::Model(format!(
                "группа {} не существует",
                p.group_id
            )));
        }
        let sort_key = self.next_sort_key(p.group_id)?;
        let now = now_ms();
        if p.created_at_ms == 0 {
            p.created_at_ms = now;
        }
        p.updated_at_ms = now;
        let data = serde_json::to_string(p).map_err(|e| StoreError::Model(e.to_string()))?;
        self.conn.execute(
            "INSERT INTO profiles (id, group_id, type, name, address, port, sort_key, favorite, notes, \
             latency_ms, full_report, tested_at_ms, uplink_total, downlink_total, data, custom_hash, \
             created_at_ms, updated_at_ms) \
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18)",
            params![
                p.id,
                p.group_id,
                type_str(p.r#type),
                p.name,
                p.address,
                p.port,
                sort_key,
                i64::from(p.favorite),
                null_str(&p.notes),
                p.test_result.latency_ms.map(i64::from),
                null_str(&p.test_result.full_report),
                p.test_result.tested_at_ms,
                p.traffic.uplink_bytes,
                p.traffic.downlink_bytes,
                data,
                null_str(&p.custom_hash),
                p.created_at_ms,
                p.updated_at_ms,
            ],
        )?;
        Ok(p.id)
    }

    /// Полностью заместить профиль (кроме sort_key и трафика/тестов). При переносе
    /// в другую группу sort_key пересчитывается. custom_hash — только из БД (T-08B).
    pub fn update_profile(&self, p: &Profile) -> Result<()> {
        if p.id == 0 {
            return Err(StoreError::Model("store: profile id is required".into()));
        }
        let (old_group, old_hash): (i64, Option<String>) = self
            .conn
            .query_row(
                "SELECT group_id, custom_hash FROM profiles WHERE id = ?1",
                [p.id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => {
                    StoreError::NotFound(format!("профиль {}", p.id))
                }
                other => StoreError::Sqlite(other),
            })?;
        let mut p = p.clone();
        p.custom_hash = old_hash.unwrap_or_default();
        p.updated_at_ms = now_ms();
        let data = serde_json::to_string(&p).map_err(|e| StoreError::Model(e.to_string()))?;
        let sort_key = if p.group_id == old_group {
            self.conn
                .query_row("SELECT sort_key FROM profiles WHERE id = ?1", [p.id], |r| {
                    r.get(0)
                })?
        } else {
            self.next_sort_key(p.group_id)?
        };
        let n = self.conn.execute(
            "UPDATE profiles SET group_id=?1, type=?2, name=?3, address=?4, port=?5, sort_key=?6, \
             favorite=?7, notes=?8, data=?9, custom_hash=?10, updated_at_ms=?11 WHERE id=?12",
            params![
                p.group_id,
                type_str(p.r#type),
                p.name,
                p.address,
                p.port,
                sort_key,
                i64::from(p.favorite),
                null_str(&p.notes),
                data,
                null_str(&p.custom_hash),
                p.updated_at_ms,
                p.id,
            ],
        )?;
        if n == 0 {
            return Err(StoreError::NotFound(format!("профиль {}", p.id)));
        }
        Ok(())
    }

    fn next_sort_key(&self, group_id: i64) -> Result<i64> {
        let max: i64 = self.conn.query_row(
            "SELECT COALESCE(MAX(sort_key), 0) FROM profiles WHERE group_id = ?1",
            [group_id],
            |r| r.get(0),
        )?;
        Ok(max + SORT_KEY_STEP)
    }
}

pub(crate) fn null_str(s: &str) -> Option<&str> {
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}
