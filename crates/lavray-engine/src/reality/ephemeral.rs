// SPDX-License-Identifier: GPL-3.0-only

//! Эфемерный x25519: приватный ключ живёт до конца handshake (два общих
//! секрета: auth с серверным ключом конфига и ecdhe с key_share hello).

pub(crate) fn fill_random(dst: &mut [u8]) {
    getrandom::fill(dst).expect("system rng");
}

pub(crate) mod x25519_compat {
    use x25519_dalek::{PublicKey, StaticSecret};

    pub struct Ephemeral {
        secret: StaticSecret,
        public: PublicKey,
        shared_config: [u8; 32],
    }

    impl Ephemeral {
        /// Сгенерировать эфемерный x25519 и вычислить auth-секрет с
        /// серверным публичным ключом конфига.
        ///
        /// # Errors
        /// Расхождение длин невозможно (все 32), но getrandom может упасть.
        pub fn new(server_public: &[u8; 32]) -> Result<Self, crate::reality::RealityError> {
            let mut seed = [0u8; 32];
            getrandom::fill(&mut seed)
                .map_err(|e| crate::reality::RealityError(format!("rng: {e}")))?;
            let secret = StaticSecret::from(seed);
            let public = PublicKey::from(&secret);
            let shared = secret.diffie_hellman(&PublicKey::from(*server_public));
            let mut shared_config = [0u8; 32];
            shared_config.copy_from_slice(shared.as_bytes());
            Ok(Self {
                secret,
                public,
                shared_config,
            })
        }

        /// Публичный ключ (32 байта).
        #[must_use]
        pub fn public(&self) -> &[u8; 32] {
            self.public.as_bytes()
        }

        /// Auth-секрет с серверным публичным ключом конфига.
        #[must_use]
        pub fn shared_config(&self) -> &[u8; 32] {
            &self.shared_config
        }

        /// ECDHE-общий секрет с key_share из ServerHello.
        ///
        /// # Errors
        /// Низкоэнтропийный секрет (невозможно с валидным peer).
        pub fn shared_ecdhe(
            &self,
            server_share: &[u8; 32],
        ) -> Result<[u8; 32], crate::reality::RealityError> {
            let shared = self.secret.diffie_hellman(&PublicKey::from(*server_share));
            if !shared.was_contributory() {
                return Err(crate::reality::RealityError("low-order ecdhe".into()));
            }
            let mut out = [0u8; 32];
            out.copy_from_slice(shared.as_bytes());
            Ok(out)
        }
    }
}
