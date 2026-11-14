// SPDX-License-Identifier: GPL-3.0-only

//! # lavray-presets
//!
//! Маршрутные пресеты LAVRay (`preset.schema.v1`) — перепись Go
//! `lavray/core/internal/presets` на Rust. Загрузка 6 builtin-наборов,
//! валидация при загрузке (SCHEMA §4), канонический JSON `Localized`,
//! пользовательские копии и id `custom:<slug>`.
//!
//! ```
//! use lavray_presets::{builtin_presets, load_preset};
//! let presets = builtin_presets().unwrap();
//! assert_eq!(presets.len(), 6);
//! assert!(presets.iter().any(|p| p.id == "lav-ru"));
//! ```

mod custom;
mod load;
mod slug;

pub mod builtin;
pub mod customrules;
pub mod limits;
pub mod localized;
mod localized_order;
pub mod process_rules;
pub mod types;
pub mod validate;

pub use builtin::{builtin_presets, builtin_source, BUILTIN_FILES};
pub use custom::{new_custom_from, prepare_user, SCHEMA_REF};
pub use customrules::{
    normalize_custom_rules, parse_custom_rules, CustomRulesError, MAX_CUSTOM_RULES_BYTES,
};
pub use load::load_preset;
pub use localized::Localized;
pub use process_rules::effective_process_rules;
pub use slug::{mint_id, slugify};
pub use types::{DnsBlock, Preset, ProcessRule, Routing, SCHEMA_VERSION};
pub use validate::ValidationError;
