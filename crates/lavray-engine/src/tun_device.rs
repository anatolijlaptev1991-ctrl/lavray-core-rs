// SPDX-License-Identifier: GPL-3.0-only

//! TUN-девайс: Unix-реализация через /dev/net/tun (ioctl TUNSETIFF).
//! Windows (wintun.dll) — заглушка с внятной ошибкой (7f-3c-4).
//! Активация только под Unix target; под Windows модуль компилируется,
//! но open() возвращает ошибку.

#![allow(dead_code)] // девайс-слой включается в 7f-3c-4 (wintun/udev интеграция)

/// Ошибка открытия TUN-девайса.
#[derive(Debug)]
pub struct DeviceError(pub String);

impl std::fmt::Display for DeviceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "tun device: {}", self.0)
    }
}

impl std::error::Error for DeviceError {}

/// Открытый TUN-девайс (Unix: fd; Windows — 7f-3c-4, wintun-хендл).
#[cfg(target_os = "linux")]
pub struct TunDevice {
    fd: std::os::fd::RawFd,
    /// Имя созданного интерфейса (tun0/…).
    pub name: String,
}

/// Не-Unix: структуры нет, open() возвращает Err.
#[cfg(not(target_os = "linux"))]
pub struct TunDevice;

impl TunDevice {
    /// Открыть TUN с именем `name` (Linux: ioctl TUNSETIFF с IFF_TUN|IFF_NO_PI).
    ///
    /// # Errors
    /// Нет /dev/net/tun, прав CAP_NET_ADMIN, или платформа не поддержана.
    #[cfg(target_os = "linux")]
    pub fn open(name: &str) -> Result<Self, DeviceError> {
        use std::os::fd::AsRawFd;

        const TUNSETIFF: libc::c_ulong = 0x400454CA;
        const IFF_TUN: libc::c_short = 0x0001;
        const IFF_NO_PI: libc::c_short = 0x1000;

        let fd = unsafe { libc::open(c"/dev/net/tun".as_ptr(), libc::O_RDWR) };
        if fd < 0 {
            return Err(DeviceError(
                "open /dev/net/tun: модуль tun не загружен или нет прав (modprobe tun; CAP_NET_ADMIN)"
                    .into(),
            ));
        }
        // ifreq: имя (16 байт) + flags (2 байта) + padding
        let mut ifreq = [0u8; 40];
        let name_bytes = name.as_bytes();
        if name_bytes.len() >= 16 {
            unsafe { libc::close(fd) };
            return Err(DeviceError("interface name too long (max 15)".into()));
        }
        ifreq[..name_bytes.len()].copy_from_slice(name_bytes);
        let flags: libc::c_short = IFF_TUN | IFF_NO_PI;
        ifreq[16..18].copy_from_slice(&flags.to_ne_bytes());

        let rc = unsafe { libc::ioctl(fd, TUNSETIFF, ifreq.as_mut_ptr()) };
        if rc < 0 {
            unsafe { libc::close(fd) };
            let err = std::io::Error::last_os_error();
            return Err(DeviceError(format!("ioctl TUNSETIFF: {err}")));
        }
        // реальное имя может быть переименовано ядром — читаем из ifreq
        let real_name = String::from_utf8_lossy(&ifreq[..16])
            .trim_end_matches('\0')
            .to_string();
        Ok(Self {
            fd: fd.as_raw_fd(),
            name: real_name,
        })
    }

    /// Не-Unix платформа: явно не поддержано в этой подволне.
    #[cfg(not(target_os = "linux"))]
    pub fn open(_name: &str) -> Result<Self, DeviceError> {
        Err(DeviceError(
            "tun device: Windows (wintun.dll) — подволна 7f-3c-4".into(),
        ))
    }

    /// Сырой дескриптор (для tokio AsyncFd в 7f-3c-4).
    #[cfg(target_os = "linux")]
    #[must_use]
    pub fn raw_fd(&self) -> std::os::fd::RawFd {
        self.fd
    }
}

#[cfg(target_os = "linux")]
impl Drop for TunDevice {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_requires_root_or_absent_device() {
        // Не-плановый тест: на CI без tun может пройти как Err, с правами — как Ok.
        // Проверяем только отсутствие паники.
        let _ = TunDevice::open("lavraytun0");
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn unsupported_platform_error() {
        match TunDevice::open("x") {
            Err(e) => assert!(e.0.contains("7f-3c-4")),
            Ok(_) => panic!("non-linux must not open tun"),
        }
    }
}
