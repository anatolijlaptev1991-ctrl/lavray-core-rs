// SPDX-License-Identifier: GPL-3.0-only

//! Разбор пресета из JSON (паритет Go `LoadPreset`).

use crate::types::Preset;
use crate::validate::ValidationError;

/// Разобрать и провалидировать пресет из JSON (паритет Go `LoadPreset`).
pub fn load_preset(data: &str) -> Result<Preset, ValidationError> {
    let preset: Preset = serde_json::from_str(data)
        .map_err(|e| ValidationError(format!("пресет: некорректный JSON: {e}")))?;
    preset
        .validate()
        .map_err(|e| ValidationError(format!("пресет {:?}: {}", preset.id, e.0)))?;
    Ok(preset)
}
