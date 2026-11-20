// SPDX-License-Identifier: GPL-3.0-only

//! Бенчи UDP wire-путей (Criterion): pack datagrams hysteria2 и
//! tuic v5 (целый и фрагментированный), unpack CommandPacket по
//! живому дампу сервера — wire-обработка без сети.

use criterion::{Criterion, criterion_group, criterion_main};
use lavray_engine::addr::TargetAddr;
use lavray_engine::udp_pipe_hy2::Hy2Udp;
use lavray_engine::udp_pipe_tuic::{pack_tuic_msg, unpack_tuic_msg};
use std::collections::HashMap;
use std::hint::black_box;

/// DNS-подобный пакет (типичный UDP-трафик туннеля).
fn dns_packet() -> Vec<u8> {
    let mut q = Vec::with_capacity(64);
    q.extend_from_slice(&[0x04, 0xd2, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
    for label in ["example", "com"] {
        let Ok(l) = u8::try_from(label.len()) else {
            break;
        };
        q.push(l);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
    q
}

fn target_dns() -> TargetAddr {
    TargetAddr::Ip(
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1)),
        53,
    )
}

/// Реальный datagram сервера (DNS-ответ 83 байта, захвачен live).
fn tuic_datagram() -> Vec<u8> {
    [
        0x05, 0x02, 0x52, 0xcf, 0x00, 0x01, 0x01, 0x00, 0x00, 0x53, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x00, 0x35, 0x04, 0xd2, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x07,
        0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00,
        0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x51, 0x7f, 0x00, 0x04, 0x5d, 0xb8,
        0xd8, 0x22, 0xc0, 0x10, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x51, 0x7f, 0x00, 0x04, 0x5d,
        0xb8, 0xd8, 0x23, 0x96, 0x00, 0x00,
    ]
    .to_vec()
}

fn bench_hy2_pack(c: &mut Criterion) {
    let dest = "1.1.1.1:53";
    let pkt = dns_packet();
    c.bench_function("hy2_pack_dns", |b| {
        b.iter(|| {
            black_box(Hy2Udp::pack_frag(
                0x1234_5678,
                1,
                0,
                1,
                dest,
                black_box(&pkt),
            ));
        });
    });
    let big = vec![7u8; 2400];
    c.bench_function("hy2_pack_frag_2400", |b| {
        b.iter(|| {
            let mut out = Vec::new();
            let mtu = 1197 - (8 + 2 + dest.len());
            for (idx, chunk) in big.chunks(mtu).enumerate() {
                let Ok(fid) = u8::try_from(idx) else { break };
                out.push(Hy2Udp::pack_frag(
                    0x1234_5678,
                    1,
                    fid,
                    3,
                    dest,
                    black_box(chunk),
                ));
            }
            black_box(out.len());
        });
    });
}

fn bench_tuic(c: &mut Criterion) {
    let target = target_dns();
    let pkt = dns_packet();
    c.bench_function("tuic_pack_dns", |b| {
        b.iter(|| {
            black_box(pack_tuic_msg(
                0x52cf,
                1,
                1,
                0,
                black_box(&target),
                black_box(&pkt),
            ));
        });
    });
    let big = vec![7u8; 2400];
    c.bench_function("tuic_pack_frag_2400", |b| {
        b.iter(|| {
            let mut out = Vec::new();
            for (idx, chunk) in big.chunks(1180).enumerate() {
                let Ok(fid) = u8::try_from(idx) else { break };
                out.push(pack_tuic_msg(0x52cf, 1, 3, fid, &target, black_box(chunk)));
            }
            black_box(out.len());
        });
    });
    let datagram = tuic_datagram();
    c.bench_function("tuic_unpack_dns", |b| {
        b.iter(|| {
            let mut f = HashMap::new();
            let _ = black_box(unpack_tuic_msg(black_box(&datagram), &mut f));
        });
    });
}

criterion_group!(benches, bench_hy2_pack, bench_tuic);
criterion_main!(benches);
