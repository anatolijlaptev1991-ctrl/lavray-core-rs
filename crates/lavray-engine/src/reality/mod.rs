// SPDX-License-Identifier: GPL-3.0-only

//! REALITY-клиент (порт common/tls/reality_client.go + свой TLS 1.3):
//! chrome-подобный ClientHello, session_id = AES-GCM(authKey, sid[:16],
//! aad=hello.Raw), authKey = HKDF-SHA256(x25519(eph, server_pub),
//! salt=random[:20], "REALITY"); верификация листа — HMAC-SHA512(authKey,
//! pub) == signature; далее обычный TLS 1.3 канал (app-ключи).

pub mod cert;
pub mod ephemeral;
pub mod handshake;
pub mod hello;
pub mod kdf;
pub mod record;
pub mod session;
pub mod stream;
pub mod verify;

use crate::reality::ephemeral::fill_random;
use crate::reality::ephemeral::x25519_compat::Ephemeral;
use crate::reality::handshake::{drive_handshake, parse_server_hello_share};
use crate::reality::kdf::Schedule;
use crate::reality::record::{read_record, write_encrypted, write_plain};
use crate::reality::session::{hkdf_real, seal_session};
use crate::reality::stream::RealityStream;
use crate::reality::verify::{build_client_finished, verify_reality};
use tokio::net::TcpStream;

/// Конфиг REALITY-подключения.
#[derive(Debug, Clone)]
pub struct RealityConfig {
    /// SNI реального сайта (публичного, за которым прячется сервер).
    pub sni: String,
    /// server public key (base64 RawURL декодированные 32 байта).
    pub public_key: [u8; 32],
    /// short_id (до 8 байт).
    pub short_id: [u8; 8],
}

/// Ошибка REALITY-рукопожатия.
#[derive(Debug)]
pub struct RealityError(pub String);

impl std::fmt::Display for RealityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "reality: {}", self.0)
    }
}

/// Результат рукопожатия: расшифрованный канал + подтверждён ли REALITY.
pub struct Handshake {
    pub stream: RealityStream,
    pub verified: bool,
}

/// Выполнить REALITY-рукопожатие поверх TCP.
///
/// # Errors
/// I/O / TLS / верификация.
pub async fn handshake(tcp: TcpStream, cfg: &RealityConfig) -> Result<Handshake, RealityError> {
    // 1. Эфемерный x25519 + общий с сервером секрет (auth key material).
    let rng = Ephemeral::new(&cfg.public_key)?;
    let shared = *rng.shared_config();

    // 2. Собрать hello со случайным random (salt/nonce) и нулевым sid.
    let mut random = [0u8; 32];
    fill_random(&mut random);
    let zero_sid = [0u8; 32];
    let hello_raw = hello::build_client_hello(&cfg.sni, &random, rng.public(), &zero_sid);

    // 3. REALITY session_id: sid[:16] = [1,8,1,?,BE32(now),short_id[8]];
    //    authKey = HKDF(shared, salt=random[:20], "REALITY") — 32 байта;
    //    sid = AES-GCM(authKey).Seal(nonce=random[20:32], sid[:16], aad=raw).
    let auth_key = hkdf_real(&shared, &random);
    let mut sid = [0u8; 32];
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    sid[0] = 1;
    sid[1] = 8;
    sid[2] = 1;
    let now32 = u32::try_from(now).unwrap_or(0);
    sid[4..8].copy_from_slice(&now32.to_be_bytes());
    sid[8..16].copy_from_slice(&cfg.short_id);
    let sealed = seal_session(&auth_key, &random, &sid[..16], &hello_raw)?;
    sid = sealed;
    let mut hello = hello_raw;
    let off = hello::session_id_offset();
    hello[off..off + 32].copy_from_slice(&sid);

    // 4. Отправить ClientHello (record type 22, legacy version 0x0301).
    let (mut tcp_r, mut tcp_w) = tokio::io::split(tcp);
    write_plain(&mut tcp_w, 22, &hello)
        .await
        .map_err(|e| RealityError(e.to_string()))?;

    // 5. ServerHello (открытая запись type 22): server random + key_share.
    let (rec_type, _, sh_payload) = read_record(&mut tcp_r)
        .await
        .map_err(|e| RealityError(e.to_string()))?;
    if rec_type != 22 {
        return Err(RealityError(format!(
            "expected server hello, got type {rec_type}"
        )));
    }
    let server_share = parse_server_hello_share(&sh_payload)?;
    let ecdhe = rng.shared_ecdhe(&server_share)?;
    // 6. Key schedule: transcript = hello + server hello payload.
    let th_hs = kdf::transcript_hash(&[&hello, &sh_payload]);
    let mut sched = Schedule::new(&ecdhe, &th_hs);

    // 7..10: handshake-фаза (фрейминг сообщений), верификация, Finished.
    let mut transcript: Vec<Vec<u8>> = vec![hello, sh_payload];
    let s_keys = sched.server_hs_keys();
    let c_keys = sched.client_hs_keys();
    let (leaf, _s_seq) = drive_handshake(&mut tcp_r, &s_keys, &mut transcript)
        .await
        .map_err(RealityError)?;

    // 9. REALITY auth: HMAC-SHA512(authKey, leaf_pub) == leaf.signature.
    let verified = verify_reality(&auth_key, leaf);

    // 10. Client Finished + app-фаза.
    let client_finished_msg = build_client_finished(
        &sched.client_hs,
        &transcript.iter().map(Vec::as_slice).collect::<Vec<_>>(),
    );
    write_encrypted(&mut tcp_w, &c_keys, 0, 22, &client_finished_msg)
        .await
        .map_err(|e| RealityError(e.to_string()))?;
    // ap-секреты: транскрипт БЕЗ client Finished — подтверждено ключлогом
    // openssl (SERVER_TRAFFIC_SECRET_0 = el(master, "s ap traffic", TH(CH…SF)))
    let th_ap = kdf::transcript_hash(&transcript.iter().map(Vec::as_slice).collect::<Vec<_>>());
    sched.derive_app(&th_ap);
    transcript.push(client_finished_msg);

    // 11. Приложение: клиентский app-канал.
    let c_ap = sched.client_ap_keys();
    let s_ap = sched.server_ap_keys();
    Ok(Handshake {
        stream: RealityStream::new(Some(tcp_r), tcp_w, c_ap, s_ap),
        verified,
    })
}

// ---- тесты ----

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_seal_round_trip() {
        let mut random = [0u8; 32];
        random[..20].fill(0x11);
        random[20..].fill(0x22);
        let mut key = [0u8; 32];
        key.fill(0x33);
        let auth = hkdf_real(&key, &random);
        let mut sid = [0u8; 32];
        sid[0] = 1;
        sid[1] = 8;
        sid[2] = 1;
        let sealed = seal_session(&auth, &random, &sid[..16], b"aad").expect("seal");
        // 16 байт данных + 16 тег — длина верна
        assert_eq!(sealed.len(), 32);
        // разные aad → другой шифртекст
        let sealed2 = seal_session(&auth, &random, &sid[..16], b"other").expect("seal");
        assert_ne!(sealed, sealed2);
    }

    #[test]
    fn server_hello_share_parse() {
        // минимальный ServerHello: type 2, len(3), version, random(32),
        // sid<1>, cipher<2>, compression<1>, ext_total<2>,
        // key_share ext: type 0033, len 34 = group(2) + key(32)
        let mut p = vec![0x02];
        p.extend_from_slice(&[0, 0, 78]); // handshake body len 78
        p.extend_from_slice(&[0x03, 0x03]); // version
        p.extend_from_slice(&[0u8; 32]); // random
        p.push(0); // sid len
        p.extend_from_slice(&[0x13, 0x01]); // cipher
        p.push(0); // compression
        p.extend_from_slice(&[0, 38]); // ext total 38
        p.extend_from_slice(&[0x00, 0x33, 0, 34, 0x00, 0x1D]);
        p.extend_from_slice(&[7u8; 32]);
        assert_eq!(p.len(), 82, "4 + 78");
        let share = parse_server_hello_share(&p).expect("parse");
        assert_eq!(share, [7u8; 32]);
    }
}
