// SPDX-License-Identifier: GPL-3.0-only

//! ValidateDnsJson (FR-UI-149): servers обязателен, dns-direct обязателен,
//! formatted — pretty-JSON (вынесено из dns.rs трещоткой размеров).

use lavray_proto::v1 as pb;
use tonic::Response;

/// Проверить и отформатировать DNS-объект. Ошибки — в теле ответа (не Status):
/// редактор показывает их списком.
pub(super) fn validate(raw: &str) -> Response<pb::ValidateDnsJsonResponse> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Response::new(pb::ValidateDnsJsonResponse {
            valid: false,
            errors: vec!["json: пустой ввод".into()],
            ..Default::default()
        });
    }
    let obj: serde_json::Map<String, serde_json::Value> = match serde_json::from_str(raw) {
        Ok(o) => o,
        Err(e) => {
            return Response::new(pb::ValidateDnsJsonResponse {
                valid: false,
                errors: vec![format!("json: {e}")],
                ..Default::default()
            });
        }
    };
    let mut errs = Vec::new();
    if !obj.contains_key("servers") {
        errs.push("servers: обязательное поле".to_string());
    }
    if !super::dns::dns_object_has_direct(&obj) {
        errs.push("servers: нужен сервер с tag \"dns-direct\"".to_string());
    }
    let formatted = serde_json::to_string_pretty(&obj).ok();
    Response::new(pb::ValidateDnsJsonResponse {
        valid: errs.is_empty(),
        errors: errs,
        formatted,
    })
}
