// SPDX-License-Identifier: GPL-3.0-only

//! LAVRay sys-обёртка: recvmsg с IP_RECVORIGDSTADDR для UDP tproxy
//! (Linux). Единственный крейт workspace с raw-syscalls — осознанное
//! исключение из политики `unsafe_code = forbid` (см. Cargo.toml):
//! tokio/socket2 не дают доступ к ancillary-данным recvmsg.
//!
//! API: `enable_recv_orig_dst(fd)` — включить приём orig-dst в cmsg;
//! `recvmsg_orig_dst(fd, buf)` — принять пакет + оригинальный dst.

#![cfg(target_os = "linux")]

use std::io;
use std::mem;
use std::net::SocketAddr;
use std::os::fd::RawFd;

use libc::{c_int, iovec, msghdr, sockaddr_in, sockaddr_in6, socklen_t};

/// Включить `IP_RECVORIGDSTADDR` на UDP-сокете (kernel вкладывает
/// оригинальный адрес назначения в cmsg каждого пакета).
///
/// # Errors
/// setsockopt (закрытый fd / без CAP при TPROXY-маршрутизации).
pub fn enable_recv_orig_dst(fd: RawFd) -> io::Result<()> {
    let on: c_int = 1;
    // SAFETY: fd валиден (владелец — живой socket), размер = размер int.
    let r = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_RECVORIGDSTADDR,
            &on as *const c_int as *const libc::c_void,
            mem::size_of::<c_int>() as socklen_t,
        )
    };
    if r == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Принять UDP-пакет вместе с оригинальным адресом назначения
/// (из cmsg `IP_RECVORIGDSTADDR`; если cmsg нет — локальный адрес).
///
/// # Errors
/// recvmsg / закрытый fd.
pub fn recvmsg_orig_dst(fd: RawFd, buf: &mut [u8]) -> io::Result<(usize, SocketAddr, SocketAddr)> {
    // msg_name: адрес отправителя пакета.
    let mut src_store = sockaddr_storage_zeroed();
    // cmsg-буфер: CMSG_SPACE(sockaddr_in6) — максимум.
    let mut ctrl = [0u8; 128];
    // musl: msghdr/iovec нельзя литералом (приватные поля паддинга и
    // отличия типов длин) — zeroed + присваивание полей (валидно и для
    // glibc: POD-структуры, нулевая инициализация эквивалентна).
    // SAFETY: POD-структуры; все поля перезаписываются ниже.
    let mut iov: iovec = unsafe { mem::zeroed() };
    iov.iov_base = buf.as_mut_ptr().cast();
    iov.iov_len = buf.len();
    // SAFETY: POD; поле за полем присваивается, паддинги нулевые.
    let mut msg: msghdr = unsafe { mem::zeroed() };
    msg.msg_name = (&mut src_store as *mut libc::sockaddr_storage).cast();
    msg.msg_namelen = mem::size_of::<libc::sockaddr_storage>() as _;
    msg.msg_iov = &raw mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = ctrl.as_mut_ptr().cast();
    msg.msg_controllen = ctrl.len() as _;
    msg.msg_flags = 0;
    // SAFETY: все буферы живы на время вызова; fd валиден.
    let n = unsafe { libc::recvmsg(fd, &mut msg, 0) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    let src = sockaddr_storage_to_addr(&src_store, msg.msg_namelen as usize)?;
    // Разбор cmsg: ищем IP_RECVORIGDSTADDR.
    let mut orig_dst = src;
    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    while !cmsg.is_null() {
        let (level, ctype, clen) = unsafe {
            (
                (*cmsg).cmsg_level,
                (*cmsg).cmsg_type,
                (*cmsg).cmsg_len as usize,
            )
        };
        if level == libc::IPPROTO_IP
            && ctype == libc::IP_RECVORIGDSTADDR
            && clen >= mem::size_of::<sockaddr_in>()
        {
            let data = unsafe { libc::CMSG_DATA(cmsg) };
            // SAFETY: cmsg data содержит sockaddr_in (или in6).
            let sa = unsafe { data.cast::<sockaddr_in>().read_unaligned() };
            orig_dst = sock_in_to_addr(&sa);
            break;
        }
        cmsg = unsafe { libc::CMSG_NXTHDR(&msg, cmsg) };
    }
    Ok((n as usize, src, orig_dst))
}

#[allow(non_snake_case)]
fn sockaddr_storage_zeroed() -> libc::sockaddr_storage {
    // SAFETY: POD-структура, нулевая инициализация валидна.
    unsafe { mem::zeroed() }
}

fn sockaddr_storage_to_addr(st: &libc::sockaddr_storage, len: usize) -> io::Result<SocketAddr> {
    match st.ss_family as c_int {
        libc::AF_INET => {
            if len < mem::size_of::<sockaddr_in>() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "short in addr"));
            }
            let sa = unsafe {
                (st as *const libc::sockaddr_storage)
                    .cast::<sockaddr_in>()
                    .read()
            };
            Ok(sock_in_to_addr(&sa))
        }
        libc::AF_INET6 => {
            if len < mem::size_of::<sockaddr_in6>() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "short in6 addr"));
            }
            let sa = unsafe {
                (st as *const libc::sockaddr_storage)
                    .cast::<sockaddr_in6>()
                    .read()
            };
            Ok(sock_in6_to_addr(&sa))
        }
        f => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("неизвестное семейство {f}"),
        )),
    }
}

fn sock_in_to_addr(sa: &sockaddr_in) -> SocketAddr {
    let ip = std::net::Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr));
    SocketAddr::new(ip.into(), u16::from_be(sa.sin_port))
}

fn sock_in6_to_addr(sa: &sockaddr_in6) -> SocketAddr {
    let ip = std::net::Ipv6Addr::from(sa.sin6_addr.s6_addr);
    SocketAddr::new(ip.into(), u16::from_be(sa.sin6_port))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket;
    use std::os::fd::AsRawFd as _;

    /// Живой тест (Linux): включить orig-dst, отправить пакет себе,
    /// recvmsg возвращает данные и orig-dst = адрес бинда.
    #[test]
    fn recvmsg_orig_dst_roundtrip() {
        let sock = UdpSocket::bind("127.0.0.1:0").expect("bind");
        let local = sock.local_addr().expect("local");
        enable_recv_orig_dst(sock.as_raw_fd()).expect("setsockopt");
        let peer = UdpSocket::bind("127.0.0.1:0").expect("bind peer");
        peer.send_to(b"hello-tproxy", local).expect("sendto");
        let mut buf = [0u8; 128];
        let (n, src, orig) = recvmsg_orig_dst(sock.as_raw_fd(), &mut buf).expect("recvmsg");
        assert_eq!(&buf[..n], b"hello-tproxy");
        assert_eq!(src.port(), peer.local_addr().expect("peer").port());
        // orig dst = адрес listener (без iptables kernel кладёт локальный dst)
        assert_eq!(orig, local);
    }
}
