// SPDX-License-Identifier: GPL-3.0-only

//! ImportNekoRayRoute: конвертация RoutingBean → новый пользовательский
//! набор (волна 6.5; вынесено из routing.rs трещоткой размеров).

#![allow(clippy::result_large_err)] // tonic::Status велик по природе контракта

use lavray_store::Store;
use std::sync::MutexGuard;
use tonic::{Response, Status};

use crate::preset_io;
use lavray_proto::v1 as pb;

pub(super) fn import_neko(
    st: &MutexGuard<'_, Store>,
    m: pb::ImportNekoRayRouteRequest,
) -> Result<Response<pb::ImportNekoRayRouteResponse>, Status> {
    let src =
        lavray_presets::parse_neko_route(&m.nekobox_json).map_err(Status::invalid_argument)?;
    let name = m.name.unwrap_or_else(|| "NekoRay".into());
    let (preset, warnings) = lavray_presets::convert_neko_route(
        &src,
        &lavray_presets::ConvertMeta {
            id: "custom:import".into(),
            name,
        },
    )
    .map_err(|e| Status::invalid_argument(e.0))?;
    let out = preset_io::insert_imported(st, preset)?;
    Ok(Response::new(pb::ImportNekoRayRouteResponse {
        preset: Some(out),
        warnings,
    }))
}
