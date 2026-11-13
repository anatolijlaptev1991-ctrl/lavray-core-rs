// SPDX-License-Identifier: GPL-3.0-only

//! Тесты хранилища: миграции, Default-группа, CRUD групп/профилей/настроек.

use lavray_model::{Detail, Group, GroupKind, Profile, ProfileType, VMessDetail};
use lavray_store::{Store, DEFAULT_GROUP_ID};
use serde_json::json;

fn vmess_profile(group_id: i64) -> Profile {
    Profile {
        group_id,
        r#type: ProfileType::VMess,
        name: "Test".into(),
        address: "example.com".into(),
        port: 443,
        detail: Some(Detail::VMess(VMessDetail {
            uuid: "uuid-1".into(),
            alter_id: 0,
            security: "auto".into(),
        })),
        ..Default::default()
    }
}

#[test]
fn migrations_create_default_group() {
    let store = Store::open_memory().unwrap();
    let groups = store.list_groups().unwrap();
    assert!(groups
        .iter()
        .any(|g| g.id == DEFAULT_GROUP_ID && g.name == "Default"));
}

#[test]
fn migrations_idempotent() {
    let store = Store::open_memory().unwrap();
    // Повторная миграция не падает и не дублирует Default.
    lavray_store::schema::migrate(store.conn()).unwrap();
    let groups = store.list_groups().unwrap();
    let defaults: Vec<_> = groups.iter().filter(|g| g.id == DEFAULT_GROUP_ID).collect();
    assert_eq!(defaults.len(), 1);
}

#[test]
fn create_and_list_group() {
    let store = Store::open_memory().unwrap();
    let g = Group {
        name: "My Group".into(),
        kind: GroupKind::Subscription,
        subscription_url: "https://example.com/sub".into(),
        ..Default::default()
    };
    let id = store.create_group(&g).unwrap();
    assert!(id > 0);
    let groups = store.list_groups().unwrap();
    let found = groups.iter().find(|x| x.id == id).unwrap();
    assert_eq!(found.name, "My Group");
    assert_eq!(found.kind, GroupKind::Subscription);
}

#[test]
fn create_and_get_profile_round_trip() {
    let store = Store::open_memory().unwrap();
    let p = vmess_profile(DEFAULT_GROUP_ID);
    let id = store.create_profile(&p, 1024).unwrap();
    let back = store.get_profile(id).unwrap();
    assert_eq!(back.id, id);
    assert_eq!(back.address, "example.com");
    assert_eq!(back.port, 443);
    assert_eq!(back.r#type, ProfileType::VMess);
    if let Some(Detail::VMess(d)) = back.detail {
        assert_eq!(d.uuid, "uuid-1");
    } else {
        panic!("VMess detail");
    }
}

#[test]
fn get_missing_profile_not_found() {
    let store = Store::open_memory().unwrap();
    assert!(store.get_profile(99999).is_err());
}

#[test]
fn count_profiles_in_group() {
    let store = Store::open_memory().unwrap();
    assert_eq!(store.count_profiles(DEFAULT_GROUP_ID).unwrap(), 0);
    store
        .create_profile(&vmess_profile(DEFAULT_GROUP_ID), 1024)
        .unwrap();
    store
        .create_profile(&vmess_profile(DEFAULT_GROUP_ID), 2048)
        .unwrap();
    assert_eq!(store.count_profiles(DEFAULT_GROUP_ID).unwrap(), 2);
}

#[test]
fn profile_cascade_on_group_delete() {
    let store = Store::open_memory().unwrap();
    let gid = store
        .create_group(&Group {
            name: "G".into(),
            ..Default::default()
        })
        .unwrap();
    store.create_profile(&vmess_profile(gid), 1024).unwrap();
    assert_eq!(store.count_profiles(gid).unwrap(), 1);
    store
        .conn()
        .execute("DELETE FROM groups WHERE id = ?1", [gid])
        .unwrap();
    assert_eq!(store.count_profiles(gid).unwrap(), 0);
}

#[test]
fn settings_set_get_round_trip() {
    let store = Store::open_memory().unwrap();
    store
        .set_setting("routing.active_preset", &json!("lav-ru"))
        .unwrap();
    let v = store.get_setting("routing.active_preset").unwrap();
    assert_eq!(v, Some(json!("lav-ru")));
}

#[test]
fn settings_upsert() {
    let store = Store::open_memory().unwrap();
    store.set_setting("k", &json!(1)).unwrap();
    store.set_setting("k", &json!(2)).unwrap();
    assert_eq!(store.get_setting("k").unwrap(), Some(json!(2)));
}

#[test]
fn settings_missing_is_none() {
    let store = Store::open_memory().unwrap();
    assert_eq!(store.get_setting("nope").unwrap(), None);
}

#[test]
fn settings_bool_and_object() {
    let store = Store::open_memory().unwrap();
    store.set_setting("remember.enable", &json!(true)).unwrap();
    store.set_setting("obj", &json!({"a": 1})).unwrap();
    assert_eq!(
        store.get_setting("remember.enable").unwrap(),
        Some(json!(true))
    );
    assert_eq!(store.get_setting("obj").unwrap(), Some(json!({"a": 1})));
}
