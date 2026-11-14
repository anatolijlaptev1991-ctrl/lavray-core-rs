// SPDX-License-Identifier: GPL-3.0-only

//! # lavray-store
//!
//! Persistence LAVRay — перепись Go `lavray/core/internal/store` на Rust
//! (sqlite, rusqlite): профили/группы/настройки, миграции. Канонический JSON
//! профиля хранится в `profiles.data` (паритет core-port-plan §5.2).

mod group_scan;
pub mod groups;
mod groups_update;
pub mod helpers;
mod profile_scan;
pub mod profiles;
mod profiles_ops;
pub mod schema;

use helpers::now_ms;
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

    /// Прочитать сырое значение meta (None если нет). Паритет Go GetMeta —
    /// пользовательские пресеты и прочие бинарные blob-ключи.
    pub fn get_meta(&self, key: &str) -> Result<Option<String>> {
        let value: Option<String> = self
            .conn
            .query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| r.get(0))
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(other),
            })?;
        Ok(value)
    }

    /// Записать сырое значение meta (upsert).
    pub fn set_meta(&self, key: &str, value: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO meta (key, value) VALUES (?1, ?2)              ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            rusqlite::params![key, value],
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
