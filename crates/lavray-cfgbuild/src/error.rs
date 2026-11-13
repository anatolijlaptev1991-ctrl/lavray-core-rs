// SPDX-License-Identifier: GPL-3.0-only

//! Ошибки конфигбилдера (порт Go `cfgbuild/errors.go`). Коды соответствуют
//! ConnectRPC/контракту lavray.v1: запрещённый ключ custom_config →
//! InvalidArgument, отсутствующий член цепочки → FailedPrecondition.

/// Код ошибки (подмножество connect.Code, нужное билдеру).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Code {
    /// INVALID_ARGUMENT.
    InvalidArgument,
    /// FAILED_PRECONDITION.
    FailedPrecondition,
}

/// Типизированная ошибка сборки: код + путь к ключу + стабильная причина.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("cfgbuild: {}", fmt_key_msg(.key, .msg))]
pub struct Error {
    /// Код ConnectRPC.
    pub code: Code,
    /// Ключ/секция конфига (напр. "inbounds", "experimental.clash_api").
    pub key: String,
    /// Стабильный код причины для ErrorInfo.reason ("" — без детали).
    pub reason: String,
    /// Человекочитаемое сообщение.
    pub msg: String,
}

fn fmt_key_msg(key: &str, msg: &str) -> String {
    if key.is_empty() {
        msg.to_string()
    } else {
        format!("{key}: {msg}")
    }
}

impl Error {
    /// INVALID_ARGUMENT с именем ключа.
    #[must_use]
    pub fn invalid(key: impl Into<String>, msg: impl Into<String>) -> Self {
        Self {
            code: Code::InvalidArgument,
            key: key.into(),
            reason: String::new(),
            msg: msg.into(),
        }
    }

    /// FAILED_PRECONDITION с именем ключа.
    #[must_use]
    pub fn precondition(key: impl Into<String>, msg: impl Into<String>) -> Self {
        Self {
            code: Code::FailedPrecondition,
            key: key.into(),
            reason: String::new(),
            msg: msg.into(),
        }
    }

    /// Задать стабильную причину (builder-паттерн).
    #[must_use]
    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = reason.into();
        self
    }
}

/// Результат операций билдера.
pub type Result<T> = std::result::Result<T, Error>;
