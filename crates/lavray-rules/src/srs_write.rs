// SPDX-License-Identifier: GPL-3.0-only

//! Запись бинарных .srs (порт srs.Write + domain.NewMatcher/newSuccinctSet):
//! magic «SRS» + version + zlib(best). Формат — паритет; DEFLATE-поток —
//! наш (чтение эталоном подтверждается round-trip тестом).

use crate::source::{DefaultRule, HeadlessRule, PlainRuleSet};
use crate::srs_build::build_succinct;
use crate::srs_enc::{
    write_ipset, write_string_slice, write_u16_slice, write_u64_slice, write_uvarint,
};

const PREFIX_LABEL: u8 = b'\r';
const ROOT_LABEL: u8 = b'\n';

/// Скомпилировать rule-set (source v3) в бинарный .srs версии 2
/// (downgrade как Go compile при отсутствии v3-полей).
///
/// # Errors
/// Ошибки сериализации (I/O).
pub fn write_ruleset(set: &PlainRuleSet) -> Result<Vec<u8>, std::io::Error> {
    let mut out = Vec::new();
    out.extend_from_slice(b"SRS");
    out.push(2);
    {
        let mut z = flate2::write::ZlibEncoder::new(&mut out, flate2::Compression::best());
        write_uvarint(&mut z, set.rules.len() as u64)?;
        for rule in &set.rules {
            write_rule(&mut z, rule)?;
        }
        z.finish()?;
    }
    Ok(out)
}

fn write_rule<W: std::io::Write>(w: &mut W, rule: &HeadlessRule) -> std::io::Result<()> {
    match rule {
        HeadlessRule::Default(d) => write_default(w, d),
        HeadlessRule::Logical(l) => {
            w.write_all(&[1])?;
            w.write_all(&[match l.mode {
                crate::source::LogicalMode::And => 0u8,
                crate::source::LogicalMode::Or => 1u8,
            }])?;
            write_uvarint(w, l.rules.len() as u64)?;
            for sub in &l.rules {
                write_rule(w, sub)?;
            }
            w.write_all(&[u8::from(l.invert)])?;
            Ok(())
        }
        HeadlessRule::Empty => Ok(()),
    }
}

fn write_default<W: std::io::Write>(w: &mut W, d: &DefaultRule) -> std::io::Result<()> {
    w.write_all(&[0])?;
    let item = |t: u8| move |w: &mut W| w.write_all(&[t]);
    if !d.query_type.is_empty() {
        item(0)(w)?;
        write_u16_slice(w, &d.query_type)?;
    }
    if !d.network.is_empty() {
        item(1)(w)?;
        write_string_slice(w, &d.network)?;
    }
    if !d.domain.is_empty() || !d.domain_suffix.is_empty() {
        w.write_all(&[2])?;
        write_succinct(w, &d.domain, &d.domain_suffix)?;
    }
    if !d.domain_keyword.is_empty() {
        item(3)(w)?;
        write_string_slice(w, &d.domain_keyword)?;
    }
    if !d.domain_regex.is_empty() {
        item(4)(w)?;
        write_string_slice(w, &d.domain_regex)?;
    }
    if !d.source_ip_cidr.is_empty() {
        w.write_all(&[5])?;
        write_ipset(w, &d.source_ip_cidr)?;
    }
    if !d.ip_cidr.is_empty() {
        w.write_all(&[6])?;
        write_ipset(w, &d.ip_cidr)?;
    }
    if !d.source_port.is_empty() {
        item(7)(w)?;
        write_u16_slice(w, &d.source_port)?;
    }
    if !d.source_port_range.is_empty() {
        item(8)(w)?;
        write_string_slice(w, &d.source_port_range)?;
    }
    if !d.port.is_empty() {
        item(9)(w)?;
        write_u16_slice(w, &d.port)?;
    }
    if !d.port_range.is_empty() {
        item(10)(w)?;
        write_string_slice(w, &d.port_range)?;
    }
    if !d.process_name.is_empty() {
        item(11)(w)?;
        write_string_slice(w, &d.process_name)?;
    }
    if !d.process_path.is_empty() {
        item(12)(w)?;
        write_string_slice(w, &d.process_path)?;
    }
    if !d.process_path_regex.is_empty() {
        item(17)(w)?;
        write_string_slice(w, &d.process_path_regex)?;
    }
    if !d.package_name.is_empty() {
        item(13)(w)?;
        write_string_slice(w, &d.package_name)?;
    }
    if !d.wifi_ssid.is_empty() {
        item(14)(w)?;
        write_string_slice(w, &d.wifi_ssid)?;
    }
    if !d.wifi_bssid.is_empty() {
        item(15)(w)?;
        write_string_slice(w, &d.wifi_bssid)?;
    }
    if !d.network_type.is_empty() {
        // v3-only; пишем как u8-слайс
        w.write_all(&[18])?;
        write_uvarint(w, d.network_type.len() as u64)?;
        let bytes: Vec<u8> = d.network_type.iter().map(|_| 0u8).collect();
        w.write_all(&bytes)?;
    }
    w.write_all(&[0xFF])?;
    w.write_all(&[u8::from(d.invert)])?;
    Ok(())
}

/// domain.Matcher.Write: byte 0 + leaves + labelBitmap + labels.
fn write_succinct<W: std::io::Write>(
    w: &mut W,
    domains: &[String],
    suffixes: &[String],
) -> std::io::Result<()> {
    // NewMatcher(domains, suffixes, legacy=false): ключи-реверсы.
    let mut keys: Vec<Vec<u8>> = Vec::with_capacity(domains.len() + suffixes.len());
    let mut seen = std::collections::HashSet::new();
    let rev = |s: &str| -> Vec<u8> { s.chars().rev().collect::<String>().into_bytes() };
    for s in suffixes {
        if !seen.insert(s.clone()) {
            continue;
        }
        if let Some(stripped) = s.strip_prefix('.') {
            let key: String = std::iter::once(PREFIX_LABEL as char)
                .chain(stripped.chars())
                .collect();
            keys.push(rev(&key));
        } else {
            let root: String = std::iter::once(ROOT_LABEL as char)
                .chain(s.chars())
                .collect();
            keys.push(rev(&root));
        }
    }
    for d in domains {
        if seen.contains(d) {
            continue;
        }
        seen.insert(d.clone());
        keys.push(rev(d));
    }
    keys.sort();
    let (leaves, label_bitmap, labels) = build_succinct(&keys);
    w.write_all(&[0])?;
    write_u64_slice(w, &leaves)?;
    write_u64_slice(w, &label_bitmap)?;
    write_uvarint(w, labels.len() as u64)?;
    w.write_all(&labels)?;
    Ok(())
}
