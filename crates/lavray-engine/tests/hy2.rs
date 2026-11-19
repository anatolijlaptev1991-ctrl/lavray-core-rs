// SPDX-License-Identifier: GPL-3.0-only

//! Тесты hysteria2 wire-формата: QUIC varint, TCP-запрос/ответ.

#[cfg(test)]
mod hy2_tests {
    use lavray_engine::hy2::{read_tcp_response, read_varint, write_tcp_request};
    use lavray_engine::hy2_config::write_varint;

    #[test]
    fn tcp_request_format() {
        let req = write_tcp_request("example.com:80", b"hi");
        // 0x401 varint (2 байта: 0x44 0x01)
        assert_eq!(&req[..2], &[0x44, 0x01]);
        let (frame, n) = read_varint(&req).expect("varint");
        assert_eq!(frame, 0x401);
        assert_eq!(n, 2);
        // addr
        let (alen, n2) = read_varint(&req[n..]).expect("alen");
        let alen_usz = usize::try_from(alen).unwrap_or(0);
        let addr = &req[n + n2..(n + n2 + alen_usz).min(req.len())];
        assert_eq!(addr, b"example.com:80");
    }

    #[test]
    fn varint_roundtrip() {
        for v in [0u64, 0x3F, 0x40, 0x3FFF, 0x4000, 0x3FFF_FFFF, 0x4000_0000] {
            let mut buf = Vec::new();
            write_varint(&mut buf, v);
            let (back, used) = read_varint(&buf).expect("read");
            assert_eq!(back, v);
            assert_eq!(used, buf.len());
        }
    }

    #[test]
    fn tcp_response_status() {
        // ok: status 0 + varint msg 0 + varint pad 0
        assert!(read_tcp_response(&[0, 0, 0]).is_ok());
        // error: status 1 + msg "boom"
        let err = read_tcp_response(&[1, 4, b'b', b'o', b'o', b'm', 0, 0]).unwrap_err();
        assert!(err.0.contains("boom"));
    }
}
