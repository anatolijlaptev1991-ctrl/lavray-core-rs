// SPDX-License-Identifier: GPL-3.0-only

//! # lavray-presets
//! Пресеты LAVRay (порт Go internal/presets): 6 builtin, SCHEMA §4,
//! канонический Localized, custom:<slug>.
//!
//! ```
//! use lavray_presets::builtin_presets;
//! assert_eq!(builtin_presets().unwrap().len(), 6);
//! ```

mod custom;
mod load;
mod neko_convert;
mod neko_custom;
mod neko_route;
mod slug;

pub mod builtin;
pub mod customrules;
pub mod limits;
pub mod localized;
mod localized_order;
pub mod process_rules;
pub mod types;
pub mod validate;

pub use builtin::{BUILTIN_FILES, builtin_presets, builtin_source};
pub use custom::{SCHEMA_REF, new_custom_from, prepare_user};
pub use customrules::{
    CustomRulesError, MAX_CUSTOM_RULES_BYTES, normalize_custom_rules, parse_custom_rules,
};
pub use load::load_preset;
pub use localized::Localized;
pub use neko_convert::{ConvertMeta, convert_neko_route};
pub use neko_route::{NekoRayRoute, parse as parse_neko_route};
pub use process_rules::effective_process_rules;
pub use slug::{mint_id, slugify};
pub use types::{DnsBlock, Preset, ProcessRule, Routing, SCHEMA_VERSION};
pub use validate::ValidationError;
