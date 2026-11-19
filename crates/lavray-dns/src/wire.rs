// SPDX-License-Identifier: GPL-3.0-only

//! Кодирование/декодирование DNS-сообщений (RFC 1035, без сжатия имён
//! при записи; при чтении — указатели 0xC0).

use crate::message::{Header, Message, ParseError, Question, RecordType, Resource};

/// Прочитать имя с сжатием (0xC0-указатели, max 10 прыжков).
fn read_name(data: &[u8], pos: &mut usize) -> Result<String, ParseError> {
    let mut labels: Vec<String> = Vec::new();
    let mut jumps = 0usize;
    let mut next: Option<usize> = None;
    let mut cur = *pos;
    loop {
        if cur >= data.len() {
            return Err(ParseError("truncated name".into()));
        }
        let len = data[cur];
        match len & 0xC0 {
            0xC0 => {
                if jumps >= 10 {
                    return Err(ParseError("too many jumps".into()));
                }
                if next.is_none() {
                    next = Some(cur + 2);
                }
                cur = (usize::from(len & 0x3F) << 8) | usize::from(data[cur + 1]);
                jumps += 1;
            }
            0x00 => {
                cur += 1;
                if len == 0 {
                    break;
                }
                let end = cur + usize::from(len);
                if end > data.len() {
                    return Err(ParseError("label out of range".into()));
                }
                labels.push(String::from_utf8_lossy(&data[cur..end]).into_owned());
                cur = end;
            }
            _ => return Err(ParseError("bad label type".into())),
        }
    }
    if let Some(n) = next {
        *pos = n;
    } else {
        *pos = cur;
    }
    Ok(if labels.is_empty() {
        ".".into()
    } else {
        labels.join(".")
    })
}

/// Записать имя (без сжатия; корень — пустой байт).
fn write_name(out: &mut Vec<u8>, name: &str) {
    if name == "." || name.is_empty() {
        out.push(0);
        return;
    }
    for label in name.split('.') {
        if label.is_empty() {
            continue;
        }
        out.push(u8::try_from(label.len().min(63)).unwrap_or(63));
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
}

/// Разобрать сообщение.
///
/// # Errors
/// Труncation/битые lengths.
pub fn parse(data: &[u8]) -> Result<Message, ParseError> {
    if data.len() < 12 {
        return Err(ParseError("truncated header".into()));
    }
    let u16_at = |i: usize| u16::from_be_bytes([data[i], data[i + 1]]);
    let mut header = Header {
        id: u16_at(0),
        flags: u16_at(2),
        qd_count: u16_at(4),
        an_count: u16_at(6),
        ns_count: u16_at(8),
        ar_count: u16_at(10),
    };
    let mut pos = 12usize;
    let mut questions = Vec::new();
    for _ in 0..header.qd_count {
        let name = read_name(data, &mut pos)?;
        if pos + 4 > data.len() {
            return Err(ParseError("truncated question".into()));
        }
        let qtype = u16_at(pos);
        let qclass = u16_at(pos + 2);
        pos += 4;
        questions.push(Question {
            name,
            qtype: RecordType::from_code(qtype),
            qclass,
        });
    }
    let mut answers = Vec::new();
    let total = usize::from(header.an_count);
    for _ in 0..total {
        let name = read_name(data, &mut pos)?;
        if pos + 10 > data.len() {
            return Err(ParseError("truncated resource header".into()));
        }
        let rtype = u16_at(pos);
        let class = u16_at(pos + 2);
        let ttl = u32::from_be_bytes([data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7]]);
        let rd_len = usize::from(u16_at(pos + 8));
        pos += 10;
        if pos + rd_len > data.len() {
            return Err(ParseError("truncated rdata".into()));
        }
        answers.push(Resource {
            name,
            rtype: RecordType::from_code(rtype),
            class,
            ttl,
            data: data[pos..pos + rd_len].to_vec(),
        });
        pos += rd_len;
    }
    header.ns_count = 0;
    header.ar_count = 0;
    Ok(Message {
        header,
        questions,
        answers,
    })
}

/// Собрать сообщение (без сжатия имён).
#[must_use]
pub fn build(msg: &Message) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&msg.header.id.to_be_bytes());
    out.extend_from_slice(&msg.header.flags.to_be_bytes());
    out.extend_from_slice(&msg.header.qd_count.to_be_bytes());
    out.extend_from_slice(&msg.header.an_count.to_be_bytes());
    out.extend_from_slice(&msg.header.ns_count.to_be_bytes());
    out.extend_from_slice(&msg.header.ar_count.to_be_bytes());
    for q in &msg.questions {
        write_name(&mut out, &q.name);
        out.extend_from_slice(&q.qtype.code().to_be_bytes());
        out.extend_from_slice(&q.qclass.to_be_bytes());
    }
    for a in &msg.answers {
        write_name(&mut out, &a.name);
        out.extend_from_slice(&a.rtype.code().to_be_bytes());
        out.extend_from_slice(&a.class.to_be_bytes());
        out.extend_from_slice(&a.ttl.to_be_bytes());
        let rd_len = u16::try_from(a.data.len()).unwrap_or(u16::MAX);
        out.extend_from_slice(&rd_len.to_be_bytes());
        out.extend_from_slice(&a.data);
    }
    out
}

/// IPv4-адрес из A-записи (4 байта).
#[must_use]
pub fn ipv4_of(data: &[u8]) -> Option<std::net::Ipv4Addr> {
    if data.len() == 4 {
        Some(std::net::Ipv4Addr::new(data[0], data[1], data[2], data[3]))
    } else {
        None
    }
}

/// IPv6-адрес из AAAA-записи (16 байт).
#[must_use]
pub fn ipv6_of(data: &[u8]) -> Option<std::net::Ipv6Addr> {
    if data.len() == 16 {
        Some(std::net::Ipv6Addr::new(
            u16::from_be_bytes([data[0], data[1]]),
            u16::from_be_bytes([data[2], data[3]]),
            u16::from_be_bytes([data[4], data[5]]),
            u16::from_be_bytes([data[6], data[7]]),
            u16::from_be_bytes([data[8], data[9]]),
            u16::from_be_bytes([data[10], data[11]]),
            u16::from_be_bytes([data[12], data[13]]),
            u16::from_be_bytes([data[14], data[15]]),
        ))
    } else {
        None
    }
}
