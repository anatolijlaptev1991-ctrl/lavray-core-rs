// SPDX-License-Identifier: GPL-3.0-only

//! lavray-dns (волна 7f-3c): DNS-модуль движка — wire-format RFC 1035,
//! UDP/DoH-транспорты, FakeIP-пул.

pub mod cidr;
pub mod doh_client;
pub mod dot_client;
pub mod fakeip;
pub mod message;
pub mod transport;
pub mod wire;

pub use dot_client::exchange_dot;
pub use fakeip::FakeIpPool;
pub use message::{
    FLAG_QR, FLAG_RA, FLAG_RD, Header, Message, ParseError, Question, RCODE_NOERROR,
    RCODE_NXDOMAIN, RecordType, Resource,
};
pub use transport::{exchange_doh, exchange_udp};
pub use wire::{build, parse};
