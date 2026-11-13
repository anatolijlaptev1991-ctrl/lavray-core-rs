// SPDX-License-Identifier: GPL-3.0-only

//! Импорт/экспорт ссылок ProfileService (волна 6): пакетный разбор share-ссылок
//! через lavray-links и генерация ссылок. Вынесено из profiles.rs ради трещотки
//! размеров (impl трейта не может быть разбит между файлами).

#![allow(clippy::result_large_err)] // tonic::Status велик по природе

use crate::profile_convert::profile_to_proto;
use lavray_proto::v1 as pb;
use lavray_store::Store;
use tonic::Status;

fn internal(e: impl std::fmt::Display) -> Status {
    Status::internal(e.to_string())
}

/// ImportContent: пакетный разбор share-ссылок в профили целевой группы.
/// preview_only возвращает разобранные профили без сохранения. Best-effort:
/// непарсируемые строки пропускаются (паритет Go ImportContent).
pub(crate) fn import_content(
    store: &Store,
    r: &pb::ImportContentRequest,
) -> pb::ImportContentResponse {
    let group_id = r.target_group_id.unwrap_or(lavray_store::DEFAULT_GROUP_ID);
    let mut parsed = Vec::new();
    let mut added = Vec::new();
    for line in r.content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Ok(mut p) = lavray_links::parse_link(line) {
            p.group_id = group_id;
            if !r.preview_only.unwrap_or(false) {
                if let Ok(id) = store.create_profile(&p) {
                    p.id = id;
                    added.push(id);
                }
            }
            parsed.push(profile_to_proto(&p));
        }
    }
    pb::ImportContentResponse {
        kind: pb::import_content_response::ContentKind::ShareLinks as i32,
        parsed_profiles: parsed,
        added_profile_ids: added,
        ..Default::default()
    }
}

/// ExportLinks: генерация share-ссылок для профилей по id или всей группе.
pub(crate) fn export_links(
    store: &Store,
    r: &pb::ExportLinksRequest,
) -> Result<pb::ExportLinksResponse, Status> {
    let profiles = if r.ids.is_empty() {
        store
            .list_profiles(r.group_id.unwrap_or(-1))
            .map_err(internal)?
    } else {
        r.ids
            .iter()
            .filter_map(|id| store.get_profile(*id).ok())
            .collect()
    };
    let links = profiles
        .iter()
        .filter_map(|p| lavray_links::build_link(p).ok())
        .collect();
    Ok(pb::ExportLinksResponse { links })
}
