// SPDX-License-Identifier: GPL-3.0-only

//! Тесты dedup-ключа (порт Go model/dedupkey.go): один и тот же сервер → один
//! ключ; переименование/статистика сервер другим не делают.

use lavray_model::{dedup_key, Profile, ProfileType};

fn server(addr: &str, port: i64) -> Profile {
    Profile {
        r#type: ProfileType::Socks,
        address: addr.into(),
        port,
        ..Default::default()
    }
}

#[test]
fn dedup_same_server_same_key() {
    assert_eq!(
        dedup_key(&server("h.com", 1080)),
        dedup_key(&server("h.com", 1080))
    );
}

#[test]
fn dedup_address_case_insensitive() {
    assert_eq!(
        dedup_key(&server("H.COM", 1080)),
        dedup_key(&server("h.com", 1080))
    );
}

#[test]
fn dedup_rename_does_not_change_key() {
    let mut a = server("h.com", 1080);
    let mut b = server("h.com", 1080);
    a.name = "Name A".into();
    b.name = "Name B".into();
    b.notes = "note".into();
    b.favorite = true;
    assert_eq!(dedup_key(&a), dedup_key(&b));
}

#[test]
fn dedup_different_port_different_key() {
    assert_ne!(
        dedup_key(&server("h.com", 1080)),
        dedup_key(&server("h.com", 1081))
    );
}

#[test]
fn dedup_different_address_different_key() {
    assert_ne!(
        dedup_key(&server("a.com", 1080)),
        dedup_key(&server("b.com", 1080))
    );
}

#[test]
fn dedup_key_is_sha256_hex() {
    let k = dedup_key(&server("h.com", 1080));
    assert_eq!(k.len(), 64);
    assert!(k.chars().all(|c| c.is_ascii_hexdigit()));
}
