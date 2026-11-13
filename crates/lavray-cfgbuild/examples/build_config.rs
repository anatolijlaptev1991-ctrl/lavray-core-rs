// SPDX-License-Identifier: GPL-3.0-only

//! Smoke-пример lavray-cfgbuild: строит sing-box конфиг из golden-входа
//! (`Gxx.in.json`) и сверяет с эталоном. Паритет `golden_test.go`:
//! полный GoldenInput (group/extra_profiles/settings/preset/preset_obj/
//! for_test/for_export). CI использует его как smoke реального библиотечного
//! кода на release-артефакте — в духе smoke lavray-linux (install + test -x).

use lavray_cfgbuild::{build, marshal_indent, BuildRequest, BuildSettings};
use lavray_model::{Group, Profile};
use lavray_presets::{builtin_presets, Preset};
use std::collections::HashMap;

#[derive(serde::Deserialize)]
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

fn main() -> std::process::ExitCode {
    let mut args = std::env::args().skip(1);
    let (Some(in_path), want) = (args.next(), args.next()) else {
        eprintln!("usage: build_config <Gxx.in.json> [want.json]");
        return std::process::ExitCode::FAILURE;
    };
    match run(&in_path, want.as_deref()) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("FAIL: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn run(in_path: &str, want_path: Option<&str>) -> Result<(), String> {
    let raw = std::fs::read_to_string(in_path).map_err(|e| format!("read {in_path}: {e}"))?;
    let input: GoldenInput =
        serde_json::from_str(&raw).map_err(|e| format!("parse {in_path}: {e}"))?;

    let mut pool: HashMap<i64, Profile> = HashMap::new();
    pool.insert(input.profile.id, input.profile.clone());
    for p in &input.extra_profiles {
        pool.insert(p.id, p.clone());
    }
    let preset = golden_preset(&input)?;

    let res = build(BuildRequest {
        profile: &input.profile,
        group: input.group.as_ref(),
        settings: input.settings.as_ref(),
        lookup: Some(&|id| {
            pool.get(&id).cloned().ok_or_else(|| {
                lavray_cfgbuild::Error::precondition("chain", format!("chain missing ent: {id}"))
            })
        }),
        preset: preset.as_ref(),
        for_test: input.for_test,
        for_export: input.for_export,
    })
    .map_err(|e| e.to_string())?;
    let got = marshal_indent(&res.config).map_err(|e| e.to_string())? + "\n";

    match want_path {
        None => print!("{got}"),
        Some(want) => {
            let expected =
                std::fs::read_to_string(want).map_err(|e| format!("read {want}: {e}"))?;
            if got != expected.replace("\r\n", "\n") {
                return Err(format!("конфиг отличается от эталона {want}"));
            }
            println!("SMOKE OK: {in_path} → байт-в-байт эталон");
        }
    }
    Ok(())
}

fn golden_preset(input: &GoldenInput) -> Result<Option<Preset>, String> {
    if !input.preset.is_empty() && input.preset_obj.is_some() {
        return Err("заданы и preset, и preset_obj".into());
    }
    if !input.preset.is_empty() {
        let builtins = builtin_presets().map_err(|e| e.0)?;
        return builtins
            .into_iter()
            .find(|p| p.id == input.preset)
            .map(Some)
            .ok_or_else(|| format!("builtin-пресет {:?} не найден", input.preset));
    }
    if let Some(p) = &input.preset_obj {
        p.validate().map_err(|e| format!("фикстура: {e}"))?;
        return Ok(Some(p.clone()));
    }
    Ok(None)
}
