// SPDX-License-Identifier: GPL-3.0-only

//! REALITY session_id: authKey и его AES-GCM-упаковка в ClientHello.

use crate::reality::RealityError;
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes128Gcm, KeyInit};
use sha2::Sha256;

const REALITY_INFO: &[u8] = b"REALITY";

/// authKey = HKDF-SHA256(ikm=shared, salt=random[:20], "REALITY").
pub(crate) fn hkdf_real(shared: &[u8], random: &[u8; 32]) -> [u8; 32] {
    let hk = hkdf::Hkdf::<Sha256>::new(Some(&random[..20]), shared);
    let mut out = [0u8; 32];
    hk.expand(REALITY_INFO, &mut out).expect("32 ok");
    out
}

/// sid = AES-128-GCM(authKey[:16]).Seal(nonce=random[20:32], sid[:16],
/// aad=hello.Raw) — 32 байта (16 данных + 16 тег).
pub(crate) fn seal_session(
    auth_key: &[u8; 32],
    random: &[u8; 32],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<[u8; 32], RealityError> {
    let cipher = Aes128Gcm::new(auth_key[..16].into());
    let nonce: [u8; 12] = random[20..32].try_into().expect("12 bytes");
    let sealed = cipher
        .encrypt(
            (&nonce).into(),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| RealityError("session seal failed".into()))?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&sealed[..32]);
    Ok(out)
}
