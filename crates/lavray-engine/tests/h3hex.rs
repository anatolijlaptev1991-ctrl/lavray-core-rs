// SPDX-License-Identifier: GPL-3.0-only
//! Отладка: hex header block auth-запроса (сравнение с Go-эталоном).
#![allow(missing_docs)]

#[test]
fn dump_auth_hex() {
    let mut headers = Vec::new();
    lavray_engine::h3_auth::push_h3_header(&mut headers, b":method", b"POST");
    lavray_engine::h3_auth::push_h3_header(&mut headers, b":scheme", b"https");
    lavray_engine::h3_auth::push_h3_header(&mut headers, b":authority", b"hysteria");
    lavray_engine::h3_auth::push_h3_header(&mut headers, b":path", b"/auth");
    lavray_engine::h3_auth::push_h3_header(&mut headers, b"hysteria-auth", b"testpw");
    lavray_engine::h3_auth::push_h3_header(&mut headers, b"hysteria-cc-rx", b"0");
    lavray_engine::h3_auth::push_h3_header(
        &mut headers,
        b"hysteria-padding",
        b"0123456789abcdefghijklmnopqrstuvwxyz",
    );
    let mut block = Vec::new();
    lavray_engine::hy2_config::write_varint(&mut block, 0);
    lavray_engine::hy2_config::write_varint(&mut block, 0);
    block.extend_from_slice(&headers);
    println!("block len={}", block.len());
    for b in &block {
        print!("{b:02x}");
    }
    println!();
}
