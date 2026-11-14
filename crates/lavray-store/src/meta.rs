// SPDX-License-Identifier: GPL-3.0-only

//! Сырые значения meta (паритет Go GetMeta/SetMeta): пользовательские
//! пресеты и прочие blob-ключи — без JSON-интерпретации значения.

use crate::{Result, Store};

impl Store {
    /// Прочитать сырое значение meta (None если нет).
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
}
