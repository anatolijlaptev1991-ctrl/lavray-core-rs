// SPDX-License-Identifier: GPL-3.0-only

//! API LAVRay (tonic); контракт lavray.v1; хранилище Arc<Mutex<Store>>.
pub mod convert;
mod dns;
mod dns_choice;
mod dns_validate;
pub mod group_convert;
mod groups_rpc;
mod preset_active;
pub mod preset_convert;
mod preset_convert_dns;
mod preset_detect;
mod preset_edit;
mod preset_io;
mod preset_plan;
mod preset_repo;
mod preset_view;
pub mod profile_convert;
mod profile_detail;
mod profile_detail_quic;
mod profile_stream;
pub mod profiles;
mod profiles_core;
mod profiles_io;
mod routing;
mod routing_neko;
mod routing_read;
pub mod settings;

pub use {
    dns::DnsServiceImpl, profiles::ProfileServiceImpl, routing::RoutingServiceImpl,
    settings::SettingsServiceImpl,
};
