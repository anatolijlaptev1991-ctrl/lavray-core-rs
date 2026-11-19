// SPDX-License-Identifier: GPL-3.0-only

//! Минимальный DER/X.509-парсер листового сертификата: ed25519-pub
//! (subjectPublicKeyInfo 1.3.101.112) и signature bitstring — для
//! REALITY-проверки HMAC-SHA512(authKey, pub) == signature.

/// Листовой сертификат: ed25519-pub (32) и сигнатура (64).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeafEd25519 {
    pub public_key: [u8; 32],
    pub signature: [u8; 64],
}

/// Разобрать DER-лист: Some(LeafEd25519) — ed25519-лист; None — другой
/// ключ (реальный сайт) или битая структура.
#[must_use]
pub fn parse_leaf_ed25519(der: &[u8]) -> Option<LeafEd25519> {
    // Certificate ::= SEQUENCE { tbsCertificate, sigAlgo, signatureValue }
    let (tbs, rest) = der_sequence(der)?;
    let (_, sig_value) = der_sequence(rest)?;
    // signatureValue: BIT STRING — сигнатура сертификата
    let signature = der_bitstring(sig_value)?;
    if signature.len() != 64 {
        return None;
    }
    // TBSCertificate ::= SEQUENCE { [0] version, serial, sigAlgo, issuer,
    // validity, subject, subjectPublicKeyInfo, ... }
    // пропустить [0] version explicit, serial, sigAlgo, issuer, validity,
    // subject — найти subjectPublicKeyInfo по OID ed25519 (1.3.101.112)
    let oid_ed25519: [u8; 5] = [0x06, 0x03, 0x2B, 0x65, 0x70];
    let idx = find_subsequence(tbs, &oid_ed25519)?;
    // OID лежит в SEQUENCE { OID, BIT STRING pub } внутри SPKI:
    // OID, затем после BIT STRING-заголовка — 32 байта pub.
    let after_oid = &tbs[idx + oid_ed25519.len()..];
    let pub_bits = der_bitstring(after_oid)?;
    if pub_bits.len() != 32 {
        return None;
    }
    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(pub_bits);
    let mut sig = [0u8; 64];
    sig.copy_from_slice(signature);
    Some(LeafEd25519 {
        public_key,
        signature: sig,
    })
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// SEQUENCE: (contents, rest) — ожидая tag 0x30.
fn der_sequence(data: &[u8]) -> Option<(&[u8], &[u8])> {
    let (content, rest, _) = der_tlv(data)?;
    Some((content, rest))
}

/// TLV: возвращает (contents, rest, tag).
fn der_tlv(data: &[u8]) -> Option<(&[u8], &[u8], u8)> {
    if data.len() < 2 {
        return None;
    }
    let tag = data[0];
    let (len, hdr) = der_len(&data[1..])?;
    let total = hdr + len;
    if data.len() < total {
        return None;
    }
    Some((&data[hdr..total], &data[total..], tag))
}

fn der_len(data: &[u8]) -> Option<(usize, usize)> {
    if data.is_empty() {
        return None;
    }
    let first = data[0];
    if first & 0x80 == 0 {
        Some((usize::from(first), 1))
    } else {
        let n = usize::from(first & 0x7F);
        if n == 0 || n > 4 || data.len() < n + 1 {
            return None;
        }
        let mut len = 0usize;
        for b in &data[1..=n] {
            len = (len << 8) | usize::from(*b);
        }
        Some((len, n + 1))
    }
}

/// BIT STRING: содержимое без 1-го «неиспользуемых бит» байта.
fn der_bitstring(data: &[u8]) -> Option<&[u8]> {
    let (content, _, tag) = der_tlv(data)?;
    if tag != 0x03 || content.is_empty() {
        return None;
    }
    Some(&content[1..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_ed25519_leaf_rejected() {
        // мусор → None
        assert!(parse_leaf_ed25519(&[0x30, 0x03, 0x02, 0x01, 0x00]).is_none());
        assert!(parse_leaf_ed25519(&[]).is_none());
    }
}
