// SPDX-License-Identifier: GPL-3.0-only

//! Схема и миграции sqlite — паритет с Go `store/migrate.go` (v1–v3).
//! Версионирование через `schema_version`; миграции идемпотентны.

use rusqlite::Connection;

/// ID группы «Default» из резервного диапазона (малые id занимает импорт NekoBox).
pub const DEFAULT_GROUP_ID: i64 = 1_000_000_000;

/// Миграции по версиям (паритет Go migrate.go v1–v3).
const MIGRATIONS: &[(i64, &[&str])] = &[
    (
        1,
        &[
            "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS groups (
               id INTEGER PRIMARY KEY,
               kind INTEGER NOT NULL DEFAULT 1,
               name TEXT NOT NULL,
               subscription_url TEXT,
               archive INTEGER NOT NULL DEFAULT 0,
               skip_auto_update INTEGER NOT NULL DEFAULT 0,
               front_proxy_id INTEGER REFERENCES profiles(id) ON DELETE SET NULL,
               subscription_info TEXT,
               update_interval_min INTEGER,
               user_agent TEXT,
               http_headers TEXT,
               http_basic_user TEXT,
               last_working_url TEXT,
               last_update_ms INTEGER,
               tab_order INTEGER NOT NULL,
               ui_state TEXT,
               created_at_ms INTEGER NOT NULL,
               updated_at_ms INTEGER NOT NULL
             )",
            "CREATE TABLE IF NOT EXISTS profiles (
               id INTEGER PRIMARY KEY,
               group_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
               type TEXT NOT NULL,
               name TEXT NOT NULL DEFAULT '',
               address TEXT NOT NULL DEFAULT '',
               port INTEGER NOT NULL DEFAULT 0,
               sort_key INTEGER NOT NULL,
               favorite INTEGER NOT NULL DEFAULT 0,
               notes TEXT,
               latency_ms INTEGER,
               full_report TEXT,
               tested_at_ms INTEGER,
               uplink_total INTEGER NOT NULL DEFAULT 0,
               downlink_total INTEGER NOT NULL DEFAULT 0,
               data TEXT NOT NULL,
               custom_confirmed INTEGER NOT NULL DEFAULT 0,
               legacy_bean TEXT,
               created_at_ms INTEGER NOT NULL,
               updated_at_ms INTEGER NOT NULL
             )",
            "CREATE INDEX IF NOT EXISTS idx_profiles_group_order ON profiles(group_id, sort_key)",
            "CREATE INDEX IF NOT EXISTS idx_profiles_dedup ON profiles(type, address, port)",
            "CREATE INDEX IF NOT EXISTS idx_profiles_favorite ON profiles(favorite) WHERE favorite <> 0",
            "CREATE TABLE IF NOT EXISTS settings (
               key TEXT PRIMARY KEY,
               value TEXT NOT NULL,
               updated_at_ms INTEGER NOT NULL
             )",
        ],
    ),
    (
        3,
        &[
            "ALTER TABLE profiles ADD COLUMN custom_hash TEXT",
            "UPDATE profiles SET custom_confirmed = 0",
        ],
    ),
];

/// Применить миграции (идемпотентно). Создаёт schema_version и Default-группу.
pub fn migrate(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_version (version INTEGER PRIMARY KEY, applied_at_ms INTEGER NOT NULL)",
    )?;
    let current: i64 = conn.query_row(
        "SELECT COALESCE(MAX(version), 0) FROM schema_version",
        [],
        |r| r.get(0),
    )?;
    for (version, stmts) in MIGRATIONS {
        if *version <= current {
            continue;
        }
        for stmt in *stmts {
            // ALTER TABLE ADD COLUMN может уже существовать при повторе — игнорируем.
            if let Err(e) = conn.execute_batch(stmt) {
                if !stmt.starts_with("ALTER TABLE") {
                    return Err(e);
                }
            }
        }
        conn.execute(
            "INSERT OR IGNORE INTO schema_version (version, applied_at_ms) VALUES (?1, ?2)",
            rusqlite::params![version, now_ms()],
        )?;
    }
    ensure_default_group(conn)?;
    Ok(())
}

/// Гарантия существования группы «Default» (паритет Go v1/v2, F4 аудита №7).
fn ensure_default_group(conn: &Connection) -> rusqlite::Result<()> {
    let now = now_ms();
    conn.execute(
        "INSERT OR IGNORE INTO groups (id, kind, name, archive, skip_auto_update, tab_order, created_at_ms, updated_at_ms)
         VALUES (?1, 1, 'Default', 0, 0, 0, ?2, ?2)",
        rusqlite::params![DEFAULT_GROUP_ID, now],
    )?;
    Ok(())
}

/// Текущее время в миллисекундах.
fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(0))
}
