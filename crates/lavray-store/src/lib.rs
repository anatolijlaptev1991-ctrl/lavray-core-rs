// SPDX-License-Identifier: GPL-3.0-only

//! # lavray-store
//!
//! Persistence LAVRay — перепись Go `lavray/core/internal/store` на Rust
//! (sqlite, rusqlite): профили/группы/настройки, миграции. Канонический JSON
//! профиля хранится в `profiles.data` (паритет core-port-plan §5.2).

pub mod helpers;
pub mod schema;

use helpers::{i64_to_kind, kind_to_i64, now_ms, type_str};
use lavray_model::{Group, Profile};
use rusqlite::Connection;
use thiserror::Error;

pub use schema::DEFAULT_GROUP_ID;

/// Ошибка хранилища.
#[derive(Debug, Error)]
pub enum StoreError {
    /// Ошибка sqlite.
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    /// Ошибка сериализации модели.
    #[error("модель: {0}")]
    Model(String),
    /// Запись не найдена.
    #[error("не найдено: {0}")]
    NotFound(String),
}

/// Результат операций хранилища.
pub type Result<T> = std::result::Result<T, StoreError>;

/// Хранилище LAVRay (sqlite).
pub struct Store {
    conn: Connection,
}

impl Store {
    /// Открыть БД в памяти (для тестов) и применить миграции.
    pub fn open_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        Self::init(conn)
    }

    /// Открыть БД по пути и применить миграции.
    pub fn open(path: &std::path::Path) -> Result<Self> {
        let conn = Connection::open(path)?;
        Self::init(conn)
    }

    fn init(conn: Connection) -> Result<Self> {
        conn.execute_batch("PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL;")?;
        schema::migrate(&conn)?;
        Ok(Self { conn })
    }

    /// Доступ к соединению (для расширенных операций).
    pub fn conn(&self) -> &Connection {
        &self.conn
    }

    // ---- Группы ----

    /// Создать группу, вернуть её id.
    pub fn create_group(&self, group: &Group) -> Result<i64> {
        let now = now_ms();
        self.conn.execute(
            "INSERT INTO groups (kind, name, subscription_url, archive, skip_auto_update, tab_order, created_at_ms, updated_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)",
            rusqlite::params![
                kind_to_i64(group.kind),
                group.name,
                group.subscription_url,
                i64::from(group.archive),
                i64::from(group.skip_auto_update),
                group.tab_order,
                now,
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Список групп в порядке tab_order.
    pub fn list_groups(&self) -> Result<Vec<Group>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, kind, name, subscription_url, archive, skip_auto_update, tab_order FROM groups ORDER BY tab_order, id",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(Group {
                id: r.get(0)?,
                kind: i64_to_kind(r.get(1)?),
                name: r.get(2)?,
                subscription_url: r.get::<_, Option<String>>(3)?.unwrap_or_default(),
                archive: r.get::<_, i64>(4)? != 0,
                skip_auto_update: r.get::<_, i64>(5)? != 0,
                tab_order: r.get(6)?,
                ..Default::default()
            })
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    // ---- Профили ----

    /// Создать профиль (канонический JSON в data), вернуть id.
    pub fn create_profile(&self, profile: &Profile, sort_key: i64) -> Result<i64> {
        let data = serde_json::to_string(profile).map_err(|e| StoreError::Model(e.to_string()))?;
        let now = now_ms();
        self.conn.execute(
            "INSERT INTO profiles (group_id, type, name, address, port, sort_key, favorite, notes, data, created_at_ms, updated_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?10)",
            rusqlite::params![
                profile.group_id,
                type_str(profile.r#type),
                profile.name,
                profile.address,
                profile.port,
                sort_key,
                i64::from(profile.favorite),
                profile.notes,
                data,
                now,
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Прочитать профиль по id.
    pub fn get_profile(&self, id: i64) -> Result<Profile> {
        let data: String = self
            .conn
            .query_row("SELECT data FROM profiles WHERE id = ?1", [id], |r| {
                r.get(0)
            })
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => {
                    StoreError::NotFound(format!("профиль {id}"))
                }
                other => StoreError::Sqlite(other),
            })?;
        let mut profile: Profile =
            serde_json::from_str(&data).map_err(|e| StoreError::Model(e.to_string()))?;
        profile.id = id;
        Ok(profile)
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

    // ---- Настройки ----

    /// Записать настройку (JSON-значение).
    pub fn set_setting(&self, key: &str, value: &serde_json::Value) -> Result<()> {
        let now = now_ms();
        self.conn.execute(
            "INSERT INTO settings (key, value, updated_at_ms) VALUES (?1, ?2, ?3)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at_ms = excluded.updated_at_ms",
            rusqlite::params![key, value.to_string(), now],
        )?;
        Ok(())
    }

    /// Прочитать настройку (None если нет).
    pub fn get_setting(&self, key: &str) -> Result<Option<serde_json::Value>> {
        let value: Option<String> = self
            .conn
            .query_row("SELECT value FROM settings WHERE key = ?1", [key], |r| {
                r.get(0)
            })
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(other),
            })?;
        match value {
            Some(v) => serde_json::from_str(&v)
                .map(Some)
                .map_err(|e| StoreError::Model(e.to_string())),
            None => Ok(None),
        }
    }
}
