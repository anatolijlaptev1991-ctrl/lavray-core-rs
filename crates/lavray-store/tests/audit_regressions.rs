// SPDX-License-Identifier: GPL-3.0-only

//! Регрессионные тесты аудита волны 4 (store): полная персистенция полей Group
//! (P2 потеря полей), непереиспользование id удалённых (L18), миграция v2,
//! гарды удаления. Regression-first: каждый баг аудита → тест навсегда.

use lavray_model::{Group, GroupKind, SubscriptionInfo};
use lavray_store::{Store, DEFAULT_GROUP_ID};
use serde_json::json;
use std::collections::BTreeMap;

fn full_group(front_id: Option<i64>) -> Group {
    let mut headers = BTreeMap::new();
    headers.insert("X-Test".to_string(), "value".to_string());
    Group {
        name: "Sub".into(),
        kind: GroupKind::Subscription,
        subscription_url: "https://example.com/sub".into(),
        front_proxy_id: front_id,
        subscription_info: Some(SubscriptionInfo {
            total_bytes: Some(1_000_000),
            expire_ms: Some(1_800_000_000_000),
            title: "My Sub".into(),
            ..Default::default()
        }),
        update_interval_min: Some(60),
        user_agent: "LAVRay/1.0".into(),
        http_headers: headers,
        http_basic_user: "user".into(),
        last_working_url: "https://mirror.example.com".into(),
        last_update_ms: 1_700_000_000_000,
        ui_state: "{\"width\":120}".into(),
        ..Default::default()
    }
}

/// Front-proxy профиль в Default-группе (FK groups.front_proxy_id → profiles.id).
fn front_proxy(store: &Store) -> i64 {
    let p = lavray_model::Profile {
        group_id: DEFAULT_GROUP_ID,
        ..Default::default()
    };
    store.create_profile(&p).unwrap()
}

#[test]
fn group_full_round_trip_no_field_loss() {
    let store = Store::open_memory().unwrap();
    let front = front_proxy(&store);
    let id = store.create_group(&full_group(Some(front))).unwrap();
    let back = store.get_group(id).unwrap();
    let src = full_group(Some(front));
    assert_eq!(back.name, src.name);
    assert_eq!(back.kind, GroupKind::Subscription);
    assert_eq!(back.subscription_url, src.subscription_url);
    assert_eq!(back.front_proxy_id, Some(front));
    assert_eq!(back.update_interval_min, Some(60));
    assert_eq!(back.user_agent, src.user_agent);
    assert_eq!(back.http_headers, src.http_headers);
    assert_eq!(back.http_basic_user, src.http_basic_user);
    assert_eq!(back.last_working_url, src.last_working_url);
    assert_eq!(back.last_update_ms, src.last_update_ms);
    assert_eq!(back.ui_state, src.ui_state);
    let info = back.subscription_info.expect("subscription_info сохранён");
    assert_eq!(info.total_bytes, Some(1_000_000));
    assert_eq!(info.title, "My Sub");
}

#[test]
fn group_list_preserves_fields() {
    let store = Store::open_memory().unwrap();
    let front = front_proxy(&store);
    let id = store.create_group(&full_group(Some(front))).unwrap();
    let groups = store.list_groups().unwrap();
    let g = groups.iter().find(|g| g.id == id).unwrap();
    assert_eq!(g.front_proxy_id, Some(front));
    assert_eq!(g.user_agent, "LAVRay/1.0");
}

#[test]
fn deleted_group_id_not_reused() {
    let store = Store::open_memory().unwrap();
    let a = store
        .create_group(&Group {
            name: "A".into(),
            ..Default::default()
        })
        .unwrap();
    let b = store
        .create_group(&Group {
            name: "B".into(),
            ..Default::default()
        })
        .unwrap();
    assert!(b > a);
    store.delete_group(b).unwrap();
    // Высоводная отметка: следующий id строго больше удалённого (L18).
    let c = store
        .create_group(&Group {
            name: "C".into(),
            ..Default::default()
        })
        .unwrap();
    assert!(
        c > b,
        "id удалённой группы не должен переиспользоваться: c={c} b={b}"
    );
}

#[test]
fn delete_last_group_rejected() {
    let store = Store::open_memory().unwrap();
    // Осталась только Default-группа → удалить нельзя (FR-UI-107).
    let err = store.delete_group(DEFAULT_GROUP_ID);
    assert!(err.is_err());
}

#[test]
fn get_missing_group_not_found() {
    let store = Store::open_memory().unwrap();
    assert!(store.get_group(999_999).is_err());
}

#[test]
fn empty_group_name_rejected() {
    let store = Store::open_memory().unwrap();
    assert!(store.create_group(&Group::default()).is_err());
}

#[test]
fn migration_v2_applied() {
    let store = Store::open_memory().unwrap();
    let max: i64 = store
        .conn()
        .query_row("SELECT MAX(version) FROM schema_version", [], |r| r.get(0))
        .unwrap();
    assert!(max >= 3, "миграции v1/v2/v3 применены, max={max}");
    let v2: i64 = store
        .conn()
        .query_row(
            "SELECT COUNT(*) FROM schema_version WHERE version = 2",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(v2, 1, "миграция v2 зафиксирована");
}

#[test]
fn migration_v2_fixes_active_preset() {
    let store = Store::open_memory().unwrap();
    // Имитируем старую установку с битым дефолтом lav-global: откатываем
    // schema_version до v1 и перезапускаем миграции — v2 чинит пресет.
    store
        .set_setting("routing.active_preset", &json!("lav-global"))
        .unwrap();
    store
        .conn()
        .execute("DELETE FROM schema_version WHERE version >= 2", [])
        .unwrap();
    lavray_store::schema::migrate(store.conn()).unwrap();
    let v = store.get_setting("routing.active_preset").unwrap();
    assert_eq!(v, Some(json!("global")));
}

#[test]
fn profile_order_computed() {
    let store = Store::open_memory().unwrap();
    let gid = store
        .create_group(&Group {
            name: "G".into(),
            ..Default::default()
        })
        .unwrap();
    let p = lavray_model::Profile {
        group_id: gid,
        ..Default::default()
    };
    let id1 = store.create_profile(&p).unwrap();
    let id2 = store.create_profile(&p).unwrap();
    // Авто sort_key: id1 раньше id2; reorder задаёт обратный порядок (FR-UI-074).
    store.reorder_profiles(gid, &[id2, id1]).unwrap();
    let g = store.get_group(gid).unwrap();
    assert_eq!(g.profile_order, vec![id2, id1], "порядок по sort_key");
}
