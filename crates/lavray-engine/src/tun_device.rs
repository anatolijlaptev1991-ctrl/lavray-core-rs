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

/// Не-Unix: структуры нет, open() возвращает Err.
#[cfg(not(target_os = "linux"))]
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
}

#[cfg(not(target_os = "linux"))]
impl TunDevice {
    /// Не-Unix платформа: явно не поддержано в этой подволне.
    ///
    /// # Errors
    /// Всегда: Windows (wintun.dll) — подволна 7f-3c-4b.
    pub fn open(_name: &str) -> Result<Self, DeviceError> {
        Err(DeviceError(
            "tun device: Windows (wintun.dll) — подволна 7f-3c-4b".into(),
        ))
    }
}
