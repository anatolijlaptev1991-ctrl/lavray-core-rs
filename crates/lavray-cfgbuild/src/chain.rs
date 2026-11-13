// SPDX-License-Identifier: GPL-3.0-only

//! Цепочки профилей → outbounds (порт Go `cfgbuild/builder.go` resolveChain +
//! buildChainOutbounds + needMuxFor). Теги: index 0 → "proxy", последний →
//! "g-<id>", промежуточные → "c-<chainId>-<id>"; detour к предыдущему.

use crate::error::{Error, Result};
use crate::filekeys::reject_file_keys;
use crate::merge::merge_json;
use crate::outbounds::build_outbound;
use crate::settings::BuildSettings;
use crate::util::{contains_str, is_ip_addr, Obj};
use crate::validate::validate_ent;
use crate::BuildResult;
use lavray_model::{Detail, Group, Profile, ProfileType};
use serde_json::{json, Value};

/// Разрешить цепочку в список профилей (порядок трафика: ents[0] — последняя
/// миля) + групповой front proxy (порт resolveChain).
pub fn resolve_chain(
    profile: &Profile,
    group: Option<&Group>,
    lookup: &dyn Fn(i64) -> Result<Profile>,
) -> Result<Vec<Profile>> {
    let mut ents = resolve_one(profile, lookup)?;
    if ents.is_empty() {
        return Err(Error::invalid(
            "chain",
            "цепочка пуста: нет профилей для outbound «proxy»",
        ));
    }
    if let Some(g) = group {
        if let Some(fid) = g.front_proxy_id {
            if fid >= 0 {
                let f = lookup(fid)
                    .map_err(|_| Error::precondition("chain", "front proxy ent not found"))?;
                ents.extend(resolve_one(&f, lookup)?);
            }
        }
    }
    Ok(ents)
}

fn resolve_one(ent: &Profile, lookup: &dyn Fn(i64) -> Result<Profile>) -> Result<Vec<Profile>> {
    if ent.r#type != ProfileType::Chain {
        return Ok(vec![ent.clone()]);
    }
    let Some(Detail::Chain(d)) = &ent.detail else {
        return Err(Error::invalid(
            "detail",
            format!("chain {}: missing or wrong detail type", ent.id),
        ));
    };
    let mut resolved = Vec::with_capacity(d.profile_ids.len());
    for id in d.profile_ids.iter().rev() {
        let m = lookup(*id)?;
        if m.r#type == ProfileType::Chain {
            return Err(Error::precondition(
                "chain",
                format!("chain in chain is not allowed: {id}"),
            ));
        }
        resolved.push(m);
    }
    Ok(resolved)
}

/// Собрать outbounds цепочки (порт buildChainOutbounds).
pub fn build_chain_outbounds(
    chain_id: i64,
    ents: &[Profile],
    st: &BuildSettings,
    res: &mut BuildResult,
) -> Result<Vec<Value>> {
    let chain_tag = format!("c-{chain_id}");
    let mut outbounds: Vec<Obj> = Vec::new();
    let mut global_profiles: Vec<i64> = Vec::new();
    let mut mux_applied = false;

    for (index, ent) in ents.iter().enumerate() {
        let mut tag_out = format!("{chain_tag}-{}", ent.id);
        let mut need_global = false;
        if index == ents.len() - 1 {
            need_global = true;
            tag_out = format!("g-{}", ent.id);
        }
        if chain_id == 0 && index == 0 {
            need_global = false;
            tag_out = "proxy".into();
        }
        if index != 0 {
            res.ignore_conn_tags.push(tag_out.clone());
        }
        if index > 0 {
            if let Some(last) = outbounds.last_mut() {
                last.insert("detour".into(), json!(tag_out));
            }
        }
        if need_global {
            if global_profiles.contains(&ent.id) {
                continue;
            }
            global_profiles.push(ent.id);
        }
        if index == 0 {
            res.outbound_tag.clone_from(&tag_out);
        }
        validate_ent(ent)?;
        let mut outbound = build_outbound(ent, st)?;
        outbound.insert("tag".into(), json!(tag_out));
        res.outbound_tags.push(tag_out.clone());

        if !mux_applied && need_mux_for(ent, &outbound, st) {
            outbound.insert(
                "multiplex".into(),
                json!({ "enabled": true, "protocol": st.mux.protocol, "padding": st.mux.padding, "max_streams": st.mux.concurrency }),
            );
            mux_applied = true;
        }

        if !ent.custom_outbound_json.is_empty() && ent.custom_fields_confirmed {
            let custom: Obj = serde_json::from_str(&ent.custom_outbound_json).map_err(|e| {
                Error::invalid(
                    "custom_outbound",
                    format!("profile {}: invalid JSON: {e}", ent.id),
                )
            })?;
            reject_file_keys("custom_outbound", &Value::Object(custom.clone()))?;
            merge_json(&mut outbound, &custom);
        }

        let mut server_address = ent.address.clone();
        if ent.r#type == ProfileType::CustomOutbound {
            if let Some(Detail::Custom(d)) = &ent.detail {
                if let Ok(o) = serde_json::from_str::<Obj>(&d.outbound_json) {
                    if let Some(s) = o.get("server").and_then(Value::as_str) {
                        if !s.is_empty() {
                            server_address = s.to_string();
                        }
                    }
                }
            }
        }
        if !server_address.is_empty() && !is_ip_addr(&server_address) {
            let full = format!("full:{server_address}");
            if !contains_str(&res.server_domains, &full) {
                res.server_domains.push(full);
            }
        }
        outbounds.push(outbound);
    }
    Ok(outbounds.into_iter().map(Value::Object).collect())
}

/// Порт needMuxFor: mux только vmess/trojan/vless; grpc/quic/tls-http выключают;
/// явное stream-решение перекрывает; flow выключает.
fn need_mux_for(ent: &Profile, outbound: &Obj, st: &BuildSettings) -> bool {
    let mut need_mux = matches!(
        ent.r#type,
        ProfileType::VMess | ProfileType::Trojan | ProfileType::Vless
    ) && st.mux.concurrency > 0;
    if let Some(s) = &ent.stream {
        if s.network == "grpc"
            || s.network == "quic"
            || (s.network == "http" && s.security == "tls")
        {
            need_mux = false;
        }
        match s.multiplex {
            0 => {
                if !st.mux.default_on {
                    need_mux = false;
                }
            }
            1 => need_mux = st.mux.concurrency > 0,
            2 => need_mux = false,
            _ => {}
        }
    }
    if ent.r#type == ProfileType::Vless
        && outbound
            .get("flow")
            .and_then(Value::as_str)
            .is_some_and(|f| !f.is_empty())
    {
        need_mux = false;
    }
    need_mux
}
