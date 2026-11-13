// SPDX-License-Identifier: GPL-3.0-only

//! Тесты встроенных пресетов: загрузка, валидация, ключевые правила lav-ru rev3.

use lavray_presets::{builtin_presets, builtin_source, load_preset, BUILTIN_FILES};

#[test]
fn all_five_builtins_load_and_validate() {
    let presets = builtin_presets().unwrap();
    assert_eq!(presets.len(), 5);
    for p in &presets {
        assert!(p.builtin, "{} должен быть builtin", p.id);
        assert!(p.validate().is_ok(), "{} невалиден", p.id);
    }
}

#[test]
fn builtin_ids_present() {
    let presets = builtin_presets().unwrap();
    let ids: Vec<&str> = presets.iter().map(|p| p.id.as_str()).collect();
    for expected in ["lav-ru", "lav-cn", "global", "all-proxy", "all-direct"] {
        assert!(ids.contains(&expected), "нет {expected}");
    }
}

#[test]
fn lav_ru_revision_3_direct_domains() {
    let presets = builtin_presets().unwrap();
    let lav_ru = presets.iter().find(|p| p.id == "lav-ru").unwrap();
    assert_eq!(lav_ru.revision, 3);
    // Rev 3: BigModel/DeepSeek/Kimi/Moonshot перенесены в direct_domain.
    for d in [
        "domain:bigmodel.cn",
        "domain:deepseek.com",
        "domain:kimi.com",
        "domain:kimi.ai",
        "domain:moonshot.cn",
        "domain:moonshot.ai",
    ] {
        assert!(
            lav_ru.routing.direct_domain.iter().any(|x| x == d),
            "{d} должен быть в direct_domain"
        );
        assert!(
            !lav_ru.routing.proxy_domain.iter().any(|x| x == d),
            "{d} не должен быть в proxy_domain"
        );
    }
}

#[test]
fn lav_ru_zai_stays_proxy() {
    let presets = builtin_presets().unwrap();
    let lav_ru = presets.iter().find(|p| p.id == "lav-ru").unwrap();
    assert!(lav_ru
        .routing
        .proxy_domain
        .iter()
        .any(|x| x == "domain:z.ai"));
}

#[test]
fn lav_ru_def_outbound_proxy() {
    let presets = builtin_presets().unwrap();
    let lav_ru = presets.iter().find(|p| p.id == "lav-ru").unwrap();
    assert_eq!(lav_ru.routing.def_outbound, "proxy");
    assert!(lav_ru.dns.routing_enabled);
}

#[test]
fn all_direct_def_outbound_direct() {
    let presets = builtin_presets().unwrap();
    let p = presets.iter().find(|p| p.id == "all-direct").unwrap();
    assert_eq!(p.routing.def_outbound, "direct");
}

#[test]
fn all_proxy_def_outbound_proxy() {
    let presets = builtin_presets().unwrap();
    let p = presets.iter().find(|p| p.id == "all-proxy").unwrap();
    assert_eq!(p.routing.def_outbound, "proxy");
}

#[test]
fn builtin_source_unknown_is_none() {
    assert!(builtin_source("nope.json").is_none());
}

#[test]
fn builtin_files_round_trip() {
    for name in BUILTIN_FILES {
        let src = builtin_source(name).unwrap();
        let p = load_preset(src).unwrap();
        assert!(p.validate().is_ok());
    }
}

#[test]
fn localized_name_has_five_langs() {
    let presets = builtin_presets().unwrap();
    let lav_ru = presets.iter().find(|p| p.id == "lav-ru").unwrap();
    for lang in ["ru", "zh", "en", "es", "de"] {
        assert!(lav_ru.name.get(lang).is_some(), "нет имени {lang}");
    }
}
