// SPDX-License-Identifier: GPL-3.0-only

//! # lavray-presets
//!
//! Маршрутные пресеты LAVRay (`preset.schema.v1`) — перепись Go
//! `lavray/core/internal/presets` на Rust. Загрузка 5 builtin-наборов,
//! валидация при загрузке (SCHEMA §4), канонический JSON `Localized`.
//!
//! ```
//! use lavray_presets::{builtin_presets, load_preset};
//! let presets = builtin_presets().unwrap();
//! assert_eq!(presets.len(), 6);
//! assert!(presets.iter().any(|p| p.id == "lav-ru"));
//! ```

pub mod builtin;
pub mod customrules;
pub mod limits;
pub mod localized;
pub mod process_rules;
pub mod types;
pub mod validate;

pub use builtin::{builtin_presets, builtin_source, BUILTIN_FILES};
pub use customrules::{
    normalize_custom_rules, parse_custom_rules, CustomRulesError, MAX_CUSTOM_RULES_BYTES,
};
pub use localized::Localized;
pub use process_rules::effective_process_rules;
pub use types::{DnsBlock, Preset, ProcessRule, Routing, SCHEMA_VERSION};
pub use validate::ValidationError;

/// Разобрать и провалидировать пресет из JSON (паритет Go `LoadPreset`).
pub fn load_preset(data: &str) -> Result<Preset, ValidationError> {
    let preset: Preset = serde_json::from_str(data)
        .map_err(|e| ValidationError(format!("пресет: некорректный JSON: {e}")))?;
    preset
        .validate()
        .map_err(|e| ValidationError(format!("пресет {:?}: {}", preset.id, e.0)))?;
    Ok(preset)
}
