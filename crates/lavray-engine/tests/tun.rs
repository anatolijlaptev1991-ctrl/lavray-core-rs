// SPDX-License-Identifier: GPL-3.0-only

//! Тесты IP/TCP/UDP разбора TUN-пакетов.

#[cfg(test)]
mod tun_tests {
    use std::net::{IpAddr, Ipv4Addr};

    use lavray_engine::tun::{L4Flow, TCP_ACK, TCP_PSH, demux, parse_ip};

    fn ipv4_tcp_packet() -> Vec<u8> {
        let mut pkt = Vec::new();
        pkt.push(0x45); // v4, ihl=5
        pkt.push(0); // tos
        pkt.extend_from_slice(&[0x00, 0x2F]); // total 47 = 20 ip + 22 tcp + 5 data
        pkt.extend_from_slice(&[0, 1, 0, 0]); // id/flags
        pkt.push(64); // ttl
        pkt.push(6); // tcp
        pkt.extend_from_slice(&[0, 0]); // checksum
        pkt.extend_from_slice(&[192, 168, 1, 5]); // src
        pkt.extend_from_slice(&[1, 1, 1, 1]); // dst
        // tcp header
        pkt.extend_from_slice(&[0x1F, 0x90]); // src 8080
        pkt.extend_from_slice(&[0x00, 0x50]); // dst 80
        pkt.extend_from_slice(&[0, 0, 0, 1]); // seq
        pkt.extend_from_slice(&[0, 0, 0, 2]); // ack
        pkt.push(0x50); // data offset
        pkt.push(TCP_PSH | TCP_ACK);
        pkt.extend_from_slice(&[0xFF, 0xFF]); // window
        pkt.extend_from_slice(&[0, 0]); // checksum (2)
        pkt.extend_from_slice(&[0, 0]); // urgent
        pkt.extend_from_slice(b"hello");
        pkt
    }

    #[test]
    fn parse_ipv4_tcp() {
        let pkt = parse_ip(&ipv4_tcp_packet()).expect("parse");
        assert_eq!(pkt.src, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5)));
        assert_eq!(pkt.dst, IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));
        assert_eq!(pkt.protocol, 6);
        let flow = demux(&pkt).expect("demux");
        match flow {
            L4Flow::Tcp {
                src_port,
                dst_port,
                flags,
                payload,
                ..
            } => {
                assert_eq!(src_port, 8080);
                assert_eq!(dst_port, 80);
                assert_eq!(flags, TCP_PSH | TCP_ACK);
                assert_eq!(payload, b"hello");
            }
            other => panic!("not tcp: {other:?}"),
        }
    }

    #[test]
    fn parse_ipv6_udp() {
        let mut pkt = vec![0x60, 0, 0, 0];
        pkt.extend_from_slice(&[0, 20]); // payload len 20
        pkt.push(17); // udp
        pkt.push(64); // hop limit
        pkt.extend_from_slice(&[0u8; 32]); // src+dst
        pkt[8] = 0x20;
        pkt[24] = 0x20; // dst starts 2001...
        // udp header: ports + len + csum
        pkt.extend_from_slice(&[0x14, 0x51]); // 5393 dns
        pkt.extend_from_slice(&[0x14, 0x51]);
        pkt.extend_from_slice(&[0, 12]);
        pkt.extend_from_slice(&[0, 0]);
        pkt.extend_from_slice(&[0u8; 4]);
        let ip = parse_ip(&pkt).expect("parse");
        assert!(matches!(ip.src, IpAddr::V6(_)));
        let flow = demux(&ip).expect("demux");
        match flow {
            L4Flow::Udp { src_port, .. } => assert_eq!(src_port, 0x1451),
            other => panic!("not udp: {other:?}"),
        }
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_ip(&[]).is_err());
        assert!(parse_ip(&[0x70, 0, 0, 0]).is_err()); // v7
        assert!(parse_ip(&[0x45u8; 10]).is_err()); // truncated
    }
}
