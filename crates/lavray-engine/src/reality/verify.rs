// SPDX-License-Identifier: GPL-3.0-only

//! REALITY-аутентификация и Client Finished.

use crate::reality::{cert, kdf};
use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha512};

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("any key");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// REALITY-аутентификация: лист ed25519, HMAC-SHA512(authKey, pub) == sig.
pub(crate) fn verify_reality(auth_key: &[u8], leaf_der: &[u8]) -> bool {
    match cert::parse_leaf_ed25519(leaf_der) {
        Some(leaf_ed) => {
            let mut mac =
                <Hmac<Sha512> as Mac>::new_from_slice(auth_key).expect("hmac any key len");
            mac.update(&leaf_ed.public_key);
            mac.finalize().into_bytes().as_slice() == &leaf_ed.signature[..]
        }
        None => false,
    }
}

/// Client Finished: MAC по транскрипту до (и включая) server Finished.
pub(crate) fn build_client_finished(client_hs_secret: &[u8], transcript: &[&[u8]]) -> Vec<u8> {
    let th = kdf::transcript_hash(transcript);
    let finished_key = kdf::finished_key(client_hs_secret);
    let mac = hmac_sha256(&finished_key, &th);
    let mut m = Vec::with_capacity(4 + mac.len());
    m.push(0x14);
    m.push(u8::try_from((mac.len() >> 16) & 0x0F).unwrap_or(0));
    m.extend_from_slice(&(u16::try_from(mac.len()).unwrap_or(u16::MAX)).to_be_bytes());
    m.extend_from_slice(&mac);
    m
}
