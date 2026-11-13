// SPDX-License-Identifier: GPL-3.0-only

//! Регрессионные тесты полного profile CRUD (порт Go store/profiles.go):
//! create/import/update/list/delete/reorder, save_test_result/save_traffic,
//! custom_hash T-08B.

use lavray_model::{Profile, ProfileType, TestResult, TrafficCounters};
use lavray_store::{Store, DEFAULT_GROUP_ID};

fn profile(name: &str) -> Profile {
    Profile {
        r#type: ProfileType::Socks,
        name: name.into(),
        address: "h.com".into(),
        port: 1080,
        group_id: DEFAULT_GROUP_ID,
        ..Default::default()
    }
}

#[test]
fn create_auto_id_and_sort_key() {
    let s = Store::open_memory().unwrap();
    let id1 = s.create_profile(&profile("a")).unwrap();
    let id2 = s.create_profile(&profile("b")).unwrap();
    assert!(id1 > 0 && id2 > id1);
    let list = s.list_profiles(DEFAULT_GROUP_ID).unwrap();
    assert_eq!(
        list.iter().map(|p| p.id).collect::<Vec<_>>(),
        vec![id1, id2]
    );
}

#[test]
fn create_nonexistent_group_rejected() {
    let s = Store::open_memory().unwrap();
    let mut p = profile("a");
    p.group_id = 999_999;
    assert!(s.create_profile(&p).is_err());
}

#[test]
fn import_preserves_id() {
    let s = Store::open_memory().unwrap();
    let mut p = profile("a");
    p.id = 42;
    let id = s.import_profile(&p).unwrap();
    assert_eq!(id, 42);
    assert_eq!(s.get_profile(42).unwrap().name, "a");
}

#[test]
fn create_resets_custom_hash() {
    let s = Store::open_memory().unwrap();
    let mut p = profile("a");
    p.custom_hash = "forged".into();
    let id = s.create_profile(&p).unwrap();
    assert!(s.get_profile(id).unwrap().custom_hash.is_empty());
}

#[test]
fn update_replaces_fields_preserves_traffic() {
    let s = Store::open_memory().unwrap();
    let id = s.create_profile(&profile("a")).unwrap();
    s.save_traffic(
        id,
        &TrafficCounters {
            uplink_bytes: 100,
            downlink_bytes: 200,
        },
    )
    .unwrap();
    let mut p = s.get_profile(id).unwrap();
    p.name = "renamed".into();
    p.traffic = TrafficCounters::default(); // клиент не должен затереть трафик
    s.update_profile(&p).unwrap();
    let back = s.get_profile(id).unwrap();
    assert_eq!(back.name, "renamed");
    assert_eq!(back.traffic.uplink_bytes, 100);
    assert_eq!(back.traffic.downlink_bytes, 200);
}

#[test]
fn update_missing_profile_not_found() {
    let s = Store::open_memory().unwrap();
    let mut p = profile("a");
    p.id = 999_999;
    assert!(s.update_profile(&p).is_err());
}

#[test]
fn save_test_result_updates_latency_and_json() {
    let s = Store::open_memory().unwrap();
    let id = s.create_profile(&profile("a")).unwrap();
    let before = s.get_profile(id).unwrap().updated_at_ms;
    let r = TestResult {
        latency_ms: Some(123),
        tested_at_ms: Some(555),
        ..Default::default()
    };
    s.save_test_result(id, &r).unwrap();
    let back = s.get_profile(id).unwrap();
    assert_eq!(back.test_result.latency_ms, Some(123));
    assert_eq!(back.test_result.tested_at_ms, Some(555));
    assert_eq!(back.updated_at_ms, before, "тест не меняет updated_at_ms");
}

#[test]
fn save_traffic_updates_counters() {
    let s = Store::open_memory().unwrap();
    let id = s.create_profile(&profile("a")).unwrap();
    s.save_traffic(
        id,
        &TrafficCounters {
            uplink_bytes: 10,
            downlink_bytes: 20,
        },
    )
    .unwrap();
    let back = s.get_profile(id).unwrap();
    assert_eq!(back.traffic.uplink_bytes, 10);
    assert_eq!(back.traffic.downlink_bytes, 20);
}

#[test]
fn list_all_with_negative_group() {
    let s = Store::open_memory().unwrap();
    s.create_profile(&profile("a")).unwrap();
    s.create_profile(&profile("b")).unwrap();
    assert_eq!(s.list_profiles(-1).unwrap().len(), 2);
    assert_eq!(s.list_profiles(DEFAULT_GROUP_ID).unwrap().len(), 2);
}

#[test]
fn delete_profile() {
    let s = Store::open_memory().unwrap();
    let id = s.create_profile(&profile("a")).unwrap();
    s.delete_profile(id).unwrap();
    assert!(s.get_profile(id).is_err());
    assert!(s.delete_profile(id).is_err());
}

#[test]
fn reorder_self_corrects_foreign_and_unlisted() {
    let s = Store::open_memory().unwrap();
    let a = s.create_profile(&profile("a")).unwrap();
    let b = s.create_profile(&profile("b")).unwrap();
    let c = s.create_profile(&profile("c")).unwrap();
    // Чужой id 999 игнорируется; неперечисленный c добавляется в конец.
    s.reorder_profiles(DEFAULT_GROUP_ID, &[b, 999, a]).unwrap();
    let order: Vec<i64> = s
        .list_profiles(DEFAULT_GROUP_ID)
        .unwrap()
        .iter()
        .map(|p| p.id)
        .collect();
    assert_eq!(order, vec![b, a, c]);
}

#[test]
fn count_profiles() {
    let s = Store::open_memory().unwrap();
    assert_eq!(s.count_profiles(DEFAULT_GROUP_ID).unwrap(), 0);
    s.create_profile(&profile("a")).unwrap();
    assert_eq!(s.count_profiles(DEFAULT_GROUP_ID).unwrap(), 1);
}
