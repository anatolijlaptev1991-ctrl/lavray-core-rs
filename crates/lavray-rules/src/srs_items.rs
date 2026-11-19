// SPDX-License-Identifier: GPL-3.0-only

//! Предметные ридеры .srs: строковые/uint16 item'ы, succinct set,
//! IP-диапазоны, адреса/префиксы (порт varbin-частей binary.go).

use crate::items::Item;

pub(crate) const ITEM_QUERY_TYPE: u8 = 0;
pub(crate) const ITEM_NETWORK: u8 = 1;
pub(crate) const ITEM_DOMAIN: u8 = 2;
pub(crate) const ITEM_DOMAIN_KEYWORD: u8 = 3;
pub(crate) const ITEM_DOMAIN_REGEX: u8 = 4;
pub(crate) const ITEM_SOURCE_IP_CIDR: u8 = 5;
pub(crate) const ITEM_IP_CIDR: u8 = 6;
pub(crate) const ITEM_SOURCE_PORT: u8 = 7;
pub(crate) const ITEM_SOURCE_PORT_RANGE: u8 = 8;
pub(crate) const ITEM_PORT: u8 = 9;
pub(crate) const ITEM_PORT_RANGE: u8 = 10;
pub(crate) const ITEM_PROCESS_NAME: u8 = 11;
pub(crate) const ITEM_PROCESS_PATH: u8 = 12;
pub(crate) const ITEM_PACKAGE_NAME: u8 = 13;
pub(crate) const ITEM_WIFI_SSID: u8 = 14;
pub(crate) const ITEM_WIFI_BSSID: u8 = 15;
pub(crate) const ITEM_ADGUARD_DOMAIN: u8 = 16;
pub(crate) const ITEM_PROCESS_PATH_REGEX: u8 = 17;
pub(crate) const ITEM_NETWORK_TYPE: u8 = 18;
// ITEM_NETWORK_IS_EXPENSIVE=19 / ITEM_NETWORK_IS_CONSTRAINED=20: с nil
// NetworkManager (CLI) item'ы опускаются — в reader не встречаются в
// матче, но коды резервируются для skip-совместимости.
#[allow(dead_code)]
pub(crate) const ITEM_NETWORK_IS_EXPENSIVE: u8 = 19;
#[allow(dead_code)]
pub(crate) const ITEM_NETWORK_IS_CONSTRAINED: u8 = 20;
pub(crate) const ITEM_NETWORK_IFACE_ADDR: u8 = 21;
pub(crate) const ITEM_DEFAULT_IFACE_ADDR: u8 = 22;
pub(crate) const ITEM_PACKAGE_NAME_REGEX: u8 = 23;
pub(crate) const ITEM_FINAL: u8 = 0xFF;

use crate::source::RuleSetParseError;
use crate::srs_reader::Reader;
use crate::succinct::SuccinctSet;
use std::net::IpAddr;

/// uint16-item'ы (query_type, порты): BE-слайс, матчинга в CLI-контексте нет.
pub(crate) fn read_u16_item(
    r: &mut Reader,
    item_type: u8,
) -> Result<Option<Item>, RuleSetParseError> {
    let field = match item_type {
        ITEM_QUERY_TYPE => Some(("query_type", 0)),
        ITEM_SOURCE_PORT => Some(("source_port", 0)),
        ITEM_PORT => Some(("port", 0)),
        _ => None,
    };
    match field {
        Some((f, _)) => {
            let n = r.uvarint_usize()?;
            r.skip(n.saturating_mul(2))?;
            Ok(Some(Item::Never(format!("{f}=<binary>"))))
        }
        None => Ok(None),
    }
}

/// Строковые item'ы (список строк, матчинг невозможен в CLI-контексте):
/// network, port_range, process_*, package_*, wifi_*.
pub(crate) fn read_string_item(
    r: &mut Reader,
    item_type: u8,
) -> Result<Option<Item>, RuleSetParseError> {
    let field = match item_type {
        ITEM_NETWORK => Some("network"),
        ITEM_SOURCE_PORT_RANGE => Some("source_port_range"),
        ITEM_PORT_RANGE => Some("port_range"),
        ITEM_PROCESS_NAME => Some("process_name"),
        ITEM_PROCESS_PATH => Some("process_path"),
        ITEM_PROCESS_PATH_REGEX => Some("process_path_regex"),
        ITEM_PACKAGE_NAME => Some("package_name"),
        ITEM_PACKAGE_NAME_REGEX => Some("package_name_regex"),
        ITEM_WIFI_SSID => Some("wifi_ssid"),
        ITEM_WIFI_BSSID => Some("wifi_bssid"),
        _ => None,
    };
    match field {
        Some(f) => Ok(Some(Item::Never(crate::strings::go_list(
            f,
            &read_strings(r)?,
        )))),
        None => Ok(None),
    }
}

pub(crate) fn read_strings(r: &mut Reader) -> Result<Vec<String>, RuleSetParseError> {
    let n = r.uvarint_usize()?;
    let mut out = Vec::with_capacity(n.min(1 << 20));
    for _ in 0..n {
        out.push(String::from_utf8_lossy(&r.bytes()?).into_owned());
    }
    Ok(out)
}

pub(crate) fn read_succinct(r: &mut Reader) -> Result<SuccinctSet, RuleSetParseError> {
    let _marker = r.u8()?;
    let leaves = r.u64_be_slice()?;
    let label_bitmap = r.u64_be_slice()?;
    let labels = r.bytes()?;
    SuccinctSet::from_parts(leaves, label_bitmap, labels).map_err(RuleSetParseError::Other)
}

pub(crate) fn read_ipset(r: &mut Reader) -> Result<Vec<(IpAddr, IpAddr)>, RuleSetParseError> {
    let version = r.u8()?;
    if version != 1 {
        return Err(RuleSetParseError::Other("invalid argument".into()));
    }
    let count = usize::try_from(r.u64_be()?)
        .map_err(|_| RuleSetParseError::Other("varint overflow".into()))?;
    let mut ranges = Vec::with_capacity(count.min(1 << 16));
    for _ in 0..count {
        let from = read_addr(r)?;
        let to = read_addr(r)?;
        ranges.push((from, to));
    }
    Ok(ranges)
}

pub(crate) fn read_addr(r: &mut Reader) -> Result<IpAddr, RuleSetParseError> {
    let len = r.uvarint_usize()?;
    if len != 4 && len != 16 {
        return Err(RuleSetParseError::Other("invalid argument".into()));
    }
    let b = r.take(len)?;
    let addr = if len == 4 {
        let mut a = [0u8; 4];
        a.copy_from_slice(b);
        IpAddr::from(a)
    } else {
        let mut a = [0u8; 16];
        a.copy_from_slice(b);
        IpAddr::from(a)
    };
    Ok(addr)
}

pub(crate) fn read_prefix(r: &mut Reader) -> Result<(), RuleSetParseError> {
    read_addr(r)?;
    r.u8()?;
    Ok(())
}
