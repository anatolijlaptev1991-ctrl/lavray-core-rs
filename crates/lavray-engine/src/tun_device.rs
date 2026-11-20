// SPDX-License-Identifier: GPL-3.0-only

//! TUN-девайс: Linux через крейт `tun` (safe-обёртка — политика
//! workspace `unsafe_code = "forbid"`). Windows (wintun.dll) — заглушка
//! до подволны 7f-3c-4b. Создание адаптера требует CAP_NET_ADMIN —
//! ручная валидация.

/// Ошибка открытия TUN-девайса.
#[derive(Debug)]
pub struct DeviceError(pub String);

impl std::fmt::Display for DeviceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "tun device: {}", self.0)
    }
}

impl std::error::Error for DeviceError {}

/// Открытый TUN-девайс (Linux).
#[cfg(target_os = "linux")]
pub struct TunDevice {
    dev: tun::platform::linux::Device,
    /// Имя интерфейса (запрошенное; реальное совпадает для TUN).
    pub name: String,
}

/// Не-Unix (кроме Windows): структуры нет, open() возвращает Err.
#[cfg(not(any(target_os = "linux", target_os = "windows")))]
pub struct TunDevice;

#[cfg(target_os = "linux")]
impl TunDevice {
    /// Открыть TUN с именем `name`.
    ///
    /// # Errors
    /// Нет /dev/net/tun, прав CAP_NET_ADMIN, или имя длиннее 15 (IFNAMSIZ-1).
    pub fn open(name: &str) -> Result<Self, DeviceError> {
        if name.len() >= 16 {
            return Err(DeviceError("interface name too long (max 15)".into()));
        }
        let dev = tun::create(tun::configure().name(name))
            .map_err(|e| DeviceError(format!("tun create: {e}")))?;
        Ok(Self {
            dev,
            name: name.to_string(),
        })
    }

    /// Ссылка на устройство (для чтения/записи пакетов в 7f-3c-4b).
    #[must_use]
    pub fn device(&self) -> &tun::platform::linux::Device {
        &self.dev
    }
}

/// Windows: wintun-адаптер через tun-rs (создание/открытие адаптера,
/// адресация через netsh — внутри крейта). Требует wintun.dll рядом с
/// исполняемым файлом (или в PATH) и прав администратора.
#[cfg(target_os = "windows")]
pub struct TunDevice {
    dev: tun::platform::windows::Device,
    /// Имя интерфейса (запрошенное).
    pub name: String,
}

#[cfg(target_os = "windows")]
impl TunDevice {
    /// Открыть/создать wintun-адаптер `name`.
    ///
    /// # Errors
    /// Нет wintun.dll, нет прав администратора, ошибка адресации.
    pub fn open(name: &str) -> Result<Self, DeviceError> {
        let dev = tun::create(tun::configure().name(name))
            .map_err(|e| DeviceError(format!("tun create (wintun): {e}")))?;
        Ok(Self {
            dev,
            name: name.to_string(),
        })
    }

    /// Ссылка на устройство (std Read/Write: IP-пакеты).
    #[must_use]
    pub fn device(&mut self) -> &mut tun::platform::windows::Device {
        &mut self.dev
    }
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
impl TunDevice {
    /// Платформа не поддержана.
    ///
    /// # Errors
    /// Всегда: платформа без TUN-реализации.
    pub fn open(_name: &str) -> Result<Self, DeviceError> {
        Err(DeviceError("tun device: платформа не поддержана".into()))
    }
}

#[cfg(target_os = "windows")]
mod wintun_io {
    //! TunIo-адаптер: std Read/Write wintun-девайса → netstack TunIo
    //! (read_packet/write_packet). Блокирующие вызовы: poll-цикл обязан
    //! жить в выделенной задаче (tun_proxy::run), а read_packet после
    //! завершения session вернёт ошибку и цикл выйдет.
    use super::TunDevice;
    use crate::netstack_types::TunIo;
    use std::io::Write;

    impl TunIo for TunDevice {
        fn read_packet(&mut self) -> std::io::Result<Vec<u8>> {
            // wintun MTU-максимум: пакет с запасом, трекаем длину
            let mut buf = vec![0u8; 65_535];
            let n = std::io::Read::read(&mut self.dev, &mut buf)?;
            buf.truncate(n);
            Ok(buf)
        }

        fn write_packet(&mut self, pkt: &[u8]) -> std::io::Result<()> {
            self.dev.write_all(pkt)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// Создание wintun-адаптера требует прав администратора и
        /// wintun.dll рядом с бинарём — ручная валидация:
        /// cargo test -p lavray-engine tun_wintun -- --ignored
        #[tokio::test]
        #[ignore = "requires admin + wintun.dll"]
        async fn tun_wintun_open_and_io() {
            let mut dev = TunDevice::open("LAVRayTest").expect("open wintun adapter");
            assert_eq!(dev.name, "LAVRayTest");
            // интерфейс готов: write невалидного пакета вернёт I/O ошибку
            // только при реальном сбое; валидный нулевой пакет длиной 0
            // просто игнорируется драйвером.
            let r = dev.write_packet(&[]);
            assert!(r.is_ok(), "write_packet: {r:?}");
            // read_packet блокирует до пакета — в тесте не читаем.
        }
    }
}

#[cfg(target_os = "linux")]
mod linux_io {
    //! TunIo-адаптер Linux: std Read/Write девайса → netstack TunIo
    //! (блокирующие вызовы — poll-цикл в выделенной задаче).
    use super::TunDevice;
    use crate::netstack_types::TunIo;
    use std::io::Write;

    impl TunIo for TunDevice {
        fn read_packet(&mut self) -> std::io::Result<Vec<u8>> {
            let mut buf = vec![0u8; 65_535];
            let n = std::io::Read::read(&mut self.dev, &mut buf)?;
            buf.truncate(n);
            Ok(buf)
        }

        fn write_packet(&mut self, pkt: &[u8]) -> std::io::Result<()> {
            self.dev.write_all(pkt)
        }
    }
}
