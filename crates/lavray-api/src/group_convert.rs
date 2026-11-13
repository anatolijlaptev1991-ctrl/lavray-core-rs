// SPDX-License-Identifier: GPL-3.0-only

//! Конверсии Group model ↔ proto (волна 6). kind — enum (Basic/Subscription).

use lavray_model::{Group, GroupKind};
use lavray_proto::v1 as pb;

fn opt(s: &str) -> Option<String> {
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

/// model Group → proto Group.
#[must_use]
pub fn group_to_proto(g: &Group) -> pb::Group {
    use pb::group::Kind;
    let kind = match g.kind {
        GroupKind::Subscription => Kind::Subscription,
        GroupKind::Basic => Kind::Basic,
    };
    pb::Group {
        id: g.id,
        name: g.name.clone(),
        kind: kind as i32,
        subscription_url: opt(&g.subscription_url),
        archive: g.archive,
        skip_auto_update: g.skip_auto_update,
        front_proxy_id: g.front_proxy_id,
        profile_order: g.profile_order.clone(),
        subscription_info: None,
        last_update_ms: if g.last_update_ms == 0 {
            None
        } else {
            Some(g.last_update_ms)
        },
        update_interval_min: g.update_interval_min,
        user_agent: opt(&g.user_agent),
        http_headers: g
            .http_headers
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        http_basic_user: opt(&g.http_basic_user),
        last_working_url: opt(&g.last_working_url),
        ui_state_json: opt(&g.ui_state),
    }
}

/// proto Group → model Group.
#[must_use]
pub fn group_from_proto(g: &pb::Group) -> Group {
    use pb::group::Kind;
    let kind = match Kind::try_from(g.kind).unwrap_or(Kind::Unspecified) {
        Kind::Subscription => GroupKind::Subscription,
        _ => GroupKind::Basic,
    };
    Group {
        id: g.id,
        name: g.name.clone(),
        kind,
        subscription_url: g.subscription_url.clone().unwrap_or_default(),
        archive: g.archive,
        skip_auto_update: g.skip_auto_update,
        front_proxy_id: g.front_proxy_id,
        profile_order: g.profile_order.clone(),
        subscription_info: None,
        last_update_ms: g.last_update_ms.unwrap_or(0),
        update_interval_min: g.update_interval_min,
        user_agent: g.user_agent.clone().unwrap_or_default(),
        http_headers: g
            .http_headers
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        http_basic_user: g.http_basic_user.clone().unwrap_or_default(),
        last_working_url: g.last_working_url.clone().unwrap_or_default(),
        ui_state: g.ui_state_json.clone().unwrap_or_default(),
        ..Default::default()
    }
}
