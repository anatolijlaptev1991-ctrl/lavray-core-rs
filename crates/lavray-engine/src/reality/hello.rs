// SPDX-License-Identifier: GPL-3.0-only

//! Сборка ClientHello в стиле Chrome (utls HelloChrome): расширения в
//! порядке Chrome, GREASE, key_share x25519, padding. REALITY патчит
//! session_id по offset 39 (handshake-заголовок 4 + версия 2 + random 32
//! + len 1).

/// Собрать тело ClientHello (handshake-сообщение целиком, без record-
/// заголовка): type 0x01 + len + body.
///
/// `random` — 32 байта (salt/nonce REALITY), `client_pub` — x25519 (32),
/// `session_id` — 32 байта (REALITY подставит шифртекст позже; здесь —
/// заполнители, патч через [`session_id_offset`]).
#[must_use]
pub fn build_client_hello(
    sni: &str,
    random: &[u8; 32],
    client_pub: &[u8; 32],
    session_id: &[u8; 32],
) -> Vec<u8> {
    let mut body = Vec::with_capacity(517);
    // legacy_version 1.2
    body.extend_from_slice(&[0x03, 0x03]);
    // random
    body.extend_from_slice(random);
    // legacy_session_id
    body.push(32);
    body.extend_from_slice(session_id);
    // cipher_suites: TLS 1.3 — ТОЛЬКО AES_128_GCM_SHA256 (наш стек
    // реализует SHA-256/AES-128; Go-сервер выбирает по клиентскому
    // порядку), TLS 1.2 — обычный chrome-набор
    let suites: [[u8; 2]; 6] = [
        [0x13, 0x01], // TLS_AES_128_GCM_SHA256
        [0xC0, 0x2B],
        [0xC0, 0x2F],
        [0xC0, 0x2C],
        [0xC0, 0x30],
        [0xCC, 0xA9],
    ];
    body.extend_from_slice(
        &u16::try_from(suites.len() * 2)
            .expect("count < 32768")
            .to_be_bytes(),
    );
    for s in &suites {
        body.extend_from_slice(s);
    }
    // compression: null
    body.extend_from_slice(&[1, 0]);

    let mut ext = Vec::new();
    // server_name
    ext_sni(&mut ext, sni);
    // extended_master_secret
    ext.extend_from_slice(&[0x00, 0x17, 0x00, 0x00]);
    // renegotiation_info (empty)
    ext.extend_from_slice(&[0xFF, 0x01, 0x00, 0x01, 0x00]);
    // supported_groups: x25519, secp256r1, secp384r1, secp521r1
    ext.extend_from_slice(&[
        0x00, 0x0A, 0x00, 0x0A, 0x00, 0x08, 0x00, 0x1D, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19,
    ]);
    // ec_point_formats: uncompressed
    ext.extend_from_slice(&[0x00, 0x0B, 0x00, 0x02, 0x01, 0x00]);
    // session_ticket (empty)
    ext.extend_from_slice(&[0x00, 0x23, 0x00, 0x00]);
    // ALPN h2, http/1.1
    ext_alpn(&mut ext);
    // status_request
    ext.extend_from_slice(&[0x00, 0x05, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00]);
    // signature_algorithms
    ext.extend_from_slice(&[
        0x00, 0x0D, 0x00, 0x12, 0x00, 0x10, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03, 0x08,
        0x05, 0x05, 0x01, 0x08, 0x06, 0x06, 0x01,
    ]);
    // key_share x25519
    ext_key_share(&mut ext, client_pub);
    // psk_key_exchange_modes: psk_dhe_ke
    ext.extend_from_slice(&[0x00, 0x2D, 0x00, 0x02, 0x01, 0x01]);
    // supported_versions: list 4 байта = [1.3, 1.2]
    ext.extend_from_slice(&[0x00, 0x2B, 0x00, 0x05, 0x04, 0x03, 0x04, 0x03, 0x03]);
    // compress_certificate: gzip
    ext.extend_from_slice(&[0x00, 0x1B, 0x00, 0x03, 0x02, 0x00, 0x02]);

    // padding: выровнять ИТОГОВОЕ сообщение (4 + body + exts) до кратности 16
    let msg_no_pad = 4 + body.len() + 2 + ext.len();
    let target = ((msg_no_pad / 16) + 1) * 16;
    let pad_needed = target.saturating_sub(msg_no_pad);
    if pad_needed >= 4 + 4 {
        // ext: type(2)+len(2)+data(pad_needed-4)
        let data_len = pad_needed - 4;
        ext.push(0x00);
        ext.push(0x15);
        ext.extend_from_slice(&(u16::try_from(data_len).unwrap_or(u16::MAX)).to_be_bytes());
        ext.extend(std::iter::repeat_n(0u8, data_len));
    }

    body.extend_from_slice(&(u16::try_from(ext.len()).unwrap_or(u16::MAX)).to_be_bytes());
    body.extend_from_slice(&ext);

    let mut msg = Vec::with_capacity(body.len() + 4);
    msg.push(0x01); // handshake type client_hello
    let body_len = body.len();
    msg.push(u8::try_from((body_len >> 16) & 0x0F).unwrap_or(0));
    msg.extend_from_slice(&(u16::try_from(body_len).unwrap_or(u16::MAX)).to_be_bytes());
    msg.extend_from_slice(&body);
    msg
}

/// Смещение session_id в handshake-сообщении (для патча REALITY).
#[must_use]
pub const fn session_id_offset() -> usize {
    39
}

fn ext_sni(ext: &mut Vec<u8>, sni: &str) {
    let mut data = Vec::with_capacity(sni.len() + 5);
    data.extend_from_slice(
        &u16::try_from(sni.len() + 3)
            .unwrap_or(u16::MAX)
            .to_be_bytes(),
    );
    data.push(0x00);
    data.extend_from_slice(&u16::try_from(sni.len()).unwrap_or(u16::MAX).to_be_bytes());
    data.extend_from_slice(sni.as_bytes());
    ext.extend_from_slice(&[0x00, 0x00]);
    ext.extend_from_slice(&u16::try_from(data.len()).unwrap_or(u16::MAX).to_be_bytes());
    ext.extend_from_slice(&data);
}

fn ext_alpn(ext: &mut Vec<u8>) {
    // только http/1.1: наш app-канал — HTTP/1.1, h2 без протокола вредит
    let list = [b"http/1.1".as_slice()];
    let mut data = Vec::new();
    let total: usize = list.iter().map(|p| p.len() + 1).sum();
    data.extend_from_slice(&u16::try_from(total).unwrap_or(u16::MAX).to_be_bytes());
    for p in &list {
        data.push(u8::try_from(p.len()).unwrap_or(u8::MAX));
        data.extend_from_slice(p);
    }
    ext.extend_from_slice(&[0x00, 0x10]);
    ext.extend_from_slice(&u16::try_from(data.len()).unwrap_or(u16::MAX).to_be_bytes());
    ext.extend_from_slice(&data);
}

fn ext_key_share(ext: &mut Vec<u8>, client_pub: &[u8; 32]) {
    // ext data = client_shares: list_len(2) + entry(group 2 + key_len 2 + key 32)
    let list_len = 2 + 2 + 32;
    let data_len = 2 + list_len;
    ext.extend_from_slice(&[0x00, 0x33]);
    ext.extend_from_slice(&u16::try_from(data_len).unwrap_or(u16::MAX).to_be_bytes());
    ext.extend_from_slice(&u16::try_from(list_len).unwrap_or(u16::MAX).to_be_bytes());
    ext.extend_from_slice(&[0x00, 0x1D]); // x25519
    ext.extend_from_slice(&32u16.to_be_bytes());
    ext.extend_from_slice(client_pub);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_structure_offsets() {
        let mut random = [0u8; 32];
        random[..20].fill(0xAA);
        random[20..].fill(0xBB);
        let mut pubk = [0u8; 32];
        pubk.fill(0xCC);
        let hello = build_client_hello("www.example.com", &random, &pubk, &[0u8; 32]);
        assert_eq!(hello[0], 0x01, "handshake type");
        assert_eq!(&hello[4..6], &[0x03, 0x03], "legacy version");
        assert_eq!(session_id_offset(), 39);
        // session_id len byte
        assert_eq!(hello[38], 32);
        // random сразу после версии
        assert_eq!(&hello[6..38], &random);
        // SNI присутствует
        assert!(hello.windows(15).any(|w| w == b"www.example.com"));
        // key_share pub присутствует
        assert!(hello.windows(32).any(|w| w == &pubk[..]));
        // supported_versions 1.3
        assert!(hello.windows(2).any(|w| w == [0x03, 0x04]));
    }
}
