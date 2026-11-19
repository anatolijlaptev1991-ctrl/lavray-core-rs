// SPDX-License-Identifier: GPL-3.0-only

//! DNS wire-format RFC 1035 (порт miekg/dns: header, question, resource):
//! разбор запросов/ответов и сборка ответов без внешних крейтов.

/// Число типов записей, поддерживаемых матчем (A/AAAA/CNAME).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordType {
    A,
    Aaaa,
    Cname,
    Other(u16),
}

impl RecordType {
    /// Код типа.
    #[must_use]
    pub fn code(self) -> u16 {
        match self {
            Self::A => 1,
            Self::Aaaa => 28,
            Self::Cname => 5,
            Self::Other(c) => c,
        }
    }
    /// Из кода.
    #[must_use]
    pub fn from_code(c: u16) -> Self {
        match c {
            1 => Self::A,
            28 => Self::Aaaa,
            5 => Self::Cname,
            other => Self::Other(other),
        }
    }
}

/// Заголовок сообщения (12 байт).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Header {
    pub id: u16,
    pub flags: u16,
    pub qd_count: u16,
    pub an_count: u16,
    pub ns_count: u16,
    pub ar_count: u16,
}

pub const FLAG_QR: u16 = 0x8000;
pub const FLAG_AA: u16 = 0x0400;
pub const FLAG_RD: u16 = 0x0100;
pub const FLAG_RA: u16 = 0x0080;
pub const RCODE_NOERROR: u16 = 0;
pub const RCODE_NXDOMAIN: u16 = 3;

/// Вопрос (имя + тип + класс).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    pub name: String,
    pub qtype: RecordType,
    pub qclass: u16,
}

/// Ресурсная запись (упрощённая: имя/тип/ttl/данные).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resource {
    pub name: String,
    pub rtype: RecordType,
    pub class: u16,
    pub ttl: u32,
    pub data: Vec<u8>,
}

/// Сообщение.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Message {
    pub header: Header,
    pub questions: Vec<Question>,
    pub answers: Vec<Resource>,
}

/// Ошибка разбора wire-формата.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError(pub String);

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "dns: {}", self.0)
    }
}

impl std::error::Error for ParseError {}
