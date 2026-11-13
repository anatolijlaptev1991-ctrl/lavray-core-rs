// SPDX-License-Identifier: GPL-3.0-only

//! Каркас сборки sing-box конфига (порт Go `cfgbuild/builder.go`
//! buildSingBoxConfig + internal-full + neutralPreset). Вынесено из lib.rs
//! ради трещотки размеров (≤200 строк на файл).

use crate::chain::{build_chain_outbounds, resolve_chain};
use crate::dns::build_dns;
use crate::error::{Error, Result};
use crate::filekeys::reject_file_keys;
use crate::inbounds::build_inbounds;
use crate::route::{build_experimental, build_route, RuleSetCollector};
use crate::settings::BuildSettings;
use crate::util::{normalize_log_level, Obj};
use crate::{BuildRequest, BuildResult};
use lavray_model::{Detail, Profile};
use lavray_presets::{DnsBlock, Preset, Routing};
use serde_json::{json, Value};

/// Каркас + outbounds + inbounds + DNS + route + experimental.
pub(crate) fn build_sing_box_config(
    req: &BuildRequest<'_>,
    st: &BuildSettings,
    res: &mut BuildResult,
) -> Result<Obj> {
    let mut cfg = Obj::new();
    cfg.insert(
        "log".into(),
        json!({ "level": normalize_log_level(&st.log_level) }),
    );

    let inbounds = build_inbounds(st, req.for_test)?;
    let lookup = |id: i64| -> Result<Profile> {
        match req.lookup {
            Some(f) => f(id),
            None => Err(Error::precondition(
                "chain",
                "profile lookup is not available",
            )),
        }
    };
    let ents = resolve_chain(req.profile, req.group, &lookup)?;
    let mut outbounds = build_chain_outbounds(0, &ents, st, res)?;
    outbounds.push(json!({ "type": "direct", "tag": "direct" }));
    outbounds.push(json!({ "type": "direct", "tag": "bypass" }));
    outbounds.push(json!({ "type": "block", "tag": "block" }));
    cfg.insert("inbounds".into(), Value::Array(inbounds));
    cfg.insert("outbounds".into(), Value::Array(outbounds));

    let neutral;
    let preset = if let Some(p) = req.preset {
        p
    } else {
        neutral = neutral_preset();
        &neutral
    };

    let mut rs = RuleSetCollector::new(st);
    let dns_obj = build_dns(preset, st, res, req.for_test, &mut rs)?;
    cfg.insert("dns".into(), Value::Object(dns_obj));
    let route_obj = build_route(preset, st, res, req.for_test, req.for_export, &mut rs)?;
    cfg.insert("route".into(), Value::Object(route_obj));

    if !req.for_test {
        cfg.insert("experimental".into(), Value::Object(build_experimental(st)));
    }
    Ok(cfg)
}

/// internal-full: конфиг ядра «как есть» из профиля + запрет путей.
pub(crate) fn internal_full_config(p: &Profile) -> Result<Obj> {
    let Some(Detail::Custom(d)) = &p.detail else {
        return Err(Error::invalid("custom", "internal-full: wrong detail type"));
    };
    let raw = d.full_config_json.trim();
    if raw.is_empty() {
        return Err(Error::invalid(
            "custom",
            "custom internal-full profile: config JSON is empty",
        ));
    }
    let cfg: Obj = serde_json::from_str(raw).map_err(|e| {
        Error::invalid(
            "custom",
            format!("custom internal-full profile: config JSON: {e}"),
        )
    })?;
    reject_file_keys("", &Value::Object(cfg.clone()))?;
    Ok(cfg)
}

/// Нейтральный пресет при Preset==None (эквивалент global, порт neutralPreset).
#[must_use]
pub fn neutral_preset() -> Preset {
    Preset {
        routing: Routing {
            def_outbound: "proxy".into(),
            sniffing_mode: 1,
            ..Default::default()
        },
        dns: DnsBlock {
            mode: "simple".into(),
            remote_dns: "https://dns.google/dns-query".into(),
            direct_dns: "local".into(),
            routing_enabled: true,
            ..Default::default()
        },
        ..Default::default()
    }
}
