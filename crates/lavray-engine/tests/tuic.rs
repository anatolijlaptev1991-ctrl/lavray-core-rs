// SPDX-License-Identifier: GPL-3.0-only

//! Тесты TUIC v5 wire-формата: auth, connect, адреса, uuid.

#[cfg(test)]
mod tuic_tests {
    use lavray_engine::addr::TargetAddr;
    use lavray_engine::tuic::{auth_request, connect_request, parse_uuid, write_addr_port};

    #[test]
    fn auth_request_format() {
        let uuid = [7u8; 16];
        let token = [9u8; 32];
        let req = auth_request(&uuid, &token);
        assert_eq!(req.len(), 2 + 16 + 32);
        assert_eq!(req[0], 5); // version
        assert_eq!(req[1], 0); // cmd authenticate
        assert_eq!(&req[2..18], &uuid);
        assert_eq!(&req[18..50], &token);
    }

    #[test]
    fn connect_request_format() {
        let t = TargetAddr::Domain("example.com".into(), 443);
        let req = connect_request(&t, b"hi");
        assert_eq!(req[0], 5);
        assert_eq!(req[1], 1); // cmd connect (sing-quic: CommandConnect = 1)
        // addr (portFirst=false): atyp(1)=00 + len(1) + host + port BE(2)
        assert_eq!(req[2], 0x00); // fqdn
        assert_eq!(req[3], 11); // len("example.com")
        assert_eq!(&req[4..15], b"example.com");
        assert_eq!(&req[15..17], &[0x01, 0xBB]); // 443
        assert_eq!(&req[17..19], b"hi");
    }

    #[test]
    fn uuid_parse() {
        let u = parse_uuid("b831381d-6324-4d53-ad4f-8cda48b30811").expect("uuid");
        assert_eq!(u[0], 0xb8);
        assert_eq!(u[15], 0x11);
        assert!(parse_uuid("short").is_err());
        assert!(parse_uuid("zz31381d-6324-4d53-ad4f-8cda48b30811").is_err());
    }

    #[test]
    fn addr_port_format() {
        let mut out = Vec::new();
        write_addr_port(&mut out, &TargetAddr::Ip("1.2.3.4".parse().unwrap(), 80));
        assert_eq!(out, vec![0x01, 1, 2, 3, 4, 0, 80]);
    }
}
