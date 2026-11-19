// SPDX-License-Identifier: GPL-3.0-only

//! # lavray-api
//!
//! API LAVRay (tonic) поверх store/cfgbuild/model; контракт lavray.v1;
//! общее хранилище Arc<Mutex<Store>>.
pub mod convert;
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

pub use profiles::ProfileServiceImpl;
pub use routing::RoutingServiceImpl;
pub use settings::SettingsServiceImpl;
