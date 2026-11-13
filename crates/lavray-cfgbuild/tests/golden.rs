// SPDX-License-Identifier: GPL-3.0-only

//! Golden-тесты конфигбилдера (паритет Go `cfgbuild/golden_test.go`): вход
//! `Gxx.in.json` (Profile + Group/extra_profiles/settings/preset), эталон
//! `Gxx.want.json` = MarshalIndent (2 пробела, ключи сортированы) + "\n".
//! Сравнение байт-в-байт. Фикстуры скопированы из Go-поставки без изменений.

use lavray_cfgbuild::{build, marshal_indent, BuildRequest, BuildSettings, Result};
use lavray_model::{Group, Profile};
use lavray_presets::{builtin_presets, Preset};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Deserialize)]
struct GoldenInput {
    profile: Profile,
    #[serde(default)]
    group: Option<Group>,
    #[serde(default)]
    extra_profiles: Vec<Profile>,
    #[serde(default)]
    settings: Option<BuildSettings>,
    #[serde(default)]
    preset: String,
    #[serde(default)]
    preset_obj: Option<Preset>,
    #[serde(default)]
    for_test: bool,
    #[serde(default)]
    for_export: bool,
}

fn golden_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/testdata/golden")
}

fn golden_preset(in_: &GoldenInput) -> Result<Option<Preset>> {
    use lavray_cfgbuild::Error;
    if !in_.preset.is_empty() && in_.preset_obj.is_some() {
        return Err(Error::precondition(
            "preset",
            "заданы и preset, и preset_obj",
        ));
    }
    if !in_.preset.is_empty() {
        let builtins = builtin_presets()
            .map_err(|e| Error::precondition("preset", format!("builtin: {e}")))?;
        return builtins
            .into_iter()
            .find(|p| p.id == in_.preset)
            .map(Some)
            .ok_or_else(|| {
                Error::precondition(
                    "preset",
                    format!("builtin-пресет {:?} не найден", in_.preset),
                )
            });
    }
    if let Some(p) = &in_.preset_obj {
        p.validate()
            .map_err(|e| Error::invalid("preset_obj", format!("фикстура: {e}")))?;
        return Ok(Some(p.clone()));
    }
    Ok(None)
}

#[test]
fn golden_byte_identical() {
    let dir = golden_dir();
    let mut paths: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            p.file_name()
                .is_some_and(|n| n.to_string_lossy().ends_with(".in.json"))
        })
        .collect();
    paths.sort();
    assert!(!paths.is_empty(), "golden-фикстуры не найдены");

    let mut failures: Vec<String> = Vec::new();
    let mut passed = 0;
    for in_path in &paths {
        let name = in_path.file_name().unwrap().to_string_lossy().to_string();
        let stem = name.trim_end_matches(".in.json");
        let raw = std::fs::read_to_string(in_path).unwrap();
        let in_: GoldenInput =
            serde_json::from_str(&raw).unwrap_or_else(|e| panic!("{name}: in.json: {e}"));

        let mut pool: HashMap<i64, Profile> = HashMap::new();
        pool.insert(in_.profile.id, in_.profile.clone());
        for p in &in_.extra_profiles {
            pool.insert(p.id, p.clone());
        }
        let preset = golden_preset(&in_).unwrap_or_else(|e| panic!("{name}: preset: {e}"));
        let lookup = |id: i64| -> Result<Profile> {
            pool.get(&id).cloned().ok_or_else(|| {
                lavray_cfgbuild::Error::precondition("chain", format!("chain missing ent: {id}"))
            })
        };
        let res = build(BuildRequest {
            profile: &in_.profile,
            group: in_.group.as_ref(),
            settings: in_.settings.as_ref(),
            lookup: Some(&lookup),
            preset: preset.as_ref(),
            for_test: in_.for_test,
            for_export: in_.for_export,
        })
        .unwrap_or_else(|e| panic!("{name}: Build: {e}"));

        let got = marshal_indent(&res.config).unwrap() + "\n";
        let want_path = dir.join(format!("{stem}.want.json"));
        // Канонический вывод Go MarshalIndent — LF; нормализуем CRLF эталона
        // (артефакт git core.autocrlf при checkout на Windows).
        let want = std::fs::read_to_string(&want_path)
            .unwrap()
            .replace("\r\n", "\n");
        if got == want {
            passed += 1;
        } else {
            failures.push(format!(
                "=== {name} ===\n--- want ---\n{want}\n--- got ---\n{got}"
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "golden: {} из {} совпали, {} расхождений:\n\n{}",
        passed,
        paths.len(),
        failures.len(),
        failures.join("\n\n")
    );
}
