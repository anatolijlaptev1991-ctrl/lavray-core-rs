// SPDX-License-Identifier: GPL-3.0-only

//! Кто читает каждую настройку каталога (хвосты A, порт Go
//! `model/settings_readers.go`). Ключ без читателя — «настройка-обманка».
//! EverySettingHasReader требует запись для каждого ключа каталога.
//! Сами таблицы — в `reader_tables`.

use std::collections::BTreeMap;

/// Вид читателя настройки.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReaderKind {
    Core,
    Shell,
    Ui,
    ImportOnly,
}

/// Читатель одной настройки.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettingReader {
    pub kind: ReaderKind,
    /// Файл читателя от корня репозитория (у import-only пуст).
    pub file: String,
    /// У import-only: почему ключ хранится, но рабочий код его не читает.
    pub reason: String,
}

pub(super) fn api(file: &str) -> SettingReader {
    SettingReader {
        kind: ReaderKind::Core,
        file: format!("core/internal/api/{file}"),
        reason: String::new(),
    }
}
pub(super) fn ui(file: &str) -> SettingReader {
    SettingReader {
        kind: ReaderKind::Ui,
        file: format!("ui/src/{file}"),
        reason: String::new(),
    }
}
pub(super) fn shell(file: &str) -> SettingReader {
    SettingReader {
        kind: ReaderKind::Shell,
        file: file.into(),
        reason: String::new(),
    }
}
pub(super) fn import_only(reason: &str) -> SettingReader {
    SettingReader {
        kind: ReaderKind::ImportOnly,
        file: String::new(),
        reason: reason.into(),
    }
}

/// Таблица «ключ → читатель»: конкатенация тематических таблиц.
#[must_use]
pub fn setting_readers() -> BTreeMap<String, SettingReader> {
    let entries: Vec<(&str, SettingReader)> = super::reader_tables::reader_tables_net()
        .into_iter()
        .chain(super::reader_tables::reader_tables_ui())
        .chain(super::reader_tables::reader_tables_misc())
        .collect();
    entries
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect()
}
