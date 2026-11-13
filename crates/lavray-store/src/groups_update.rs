// SPDX-License-Identifier: GPL-3.0-only

//! Обновление и упорядочение групп (порт Go `store/groups.go`
//! UpdateGroup/ReorderGroups). Вынесено из groups.rs ради трещотки размеров.

use crate::group_scan::{null_ms, null_str};
use crate::helpers::now_ms;
use crate::{Result, Store, StoreError};
use lavray_model::Group;
use rusqlite::params;

impl Store {
    /// Обновить изменяемые поля группы. kind после создания не меняется
    /// (FR-UI-109); id/created_at_ms тоже.
    pub fn update_group(&self, g: &Group) -> Result<()> {
        if g.id == 0 {
            return Err(StoreError::Model("store: group id is required".into()));
        }
        let sub_info = g
            .subscription_info
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(|e| StoreError::Model(e.to_string()))?;
        let headers = if g.http_headers.is_empty() {
            None
        } else {
            Some(
                serde_json::to_string(&g.http_headers)
                    .map_err(|e| StoreError::Model(e.to_string()))?,
            )
        };
        let n = self.conn.execute(
            "UPDATE groups SET name=?1, subscription_url=?2, archive=?3, skip_auto_update=?4, \
             front_proxy_id=?5, subscription_info=?6, update_interval_min=?7, user_agent=?8, \
             http_headers=?9, http_basic_user=?10, last_working_url=?11, last_update_ms=?12, \
             ui_state=?13, updated_at_ms=?14 WHERE id=?15",
            params![
                g.name,
                null_str(&g.subscription_url),
                i64::from(g.archive),
                i64::from(g.skip_auto_update),
                g.front_proxy_id,
                sub_info,
                g.update_interval_min,
                null_str(&g.user_agent),
                headers,
                null_str(&g.http_basic_user),
                null_str(&g.last_working_url),
                null_ms(g.last_update_ms),
                null_str(&g.ui_state),
                now_ms(),
                g.id,
            ],
        )?;
        if n == 0 {
            return Err(StoreError::NotFound(format!("группа {}", g.id)));
        }
        Ok(())
    }

    /// Порядок вкладок групп (FR-UI-113): перечисленные id получают порядок
    /// перечисления; неперечисленные сохраняют прежний порядок.
    pub fn reorder_groups(&self, ordered_ids: &[i64]) -> Result<()> {
        for (i, id) in ordered_ids.iter().enumerate() {
            let order = i64::try_from(i + 1).unwrap_or(i64::MAX);
            self.conn.execute(
                "UPDATE groups SET tab_order = ?1 WHERE id = ?2",
                params![order, id],
            )?;
        }
        Ok(())
    }
}
