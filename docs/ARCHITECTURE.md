# Архитектура LAVRay Core (Rust)

Перепись Go-ядра `lavray/core` на Rust. Этот документ фиксирует архитектуру,
границу с прокси-движком и стандарты качества. Поэтапный план — [ROADMAP.md](ROADMAP.md).

## Два слоя ядра

Go-ядро состоит из двух частей, и перепись разделяет их так же:

1. **管理层 LAVRay** (LAVRay-specific management) — то, что переписывается
   полностью на Rust: API (ConnectRPC), профили/подписки, построение конфига,
   маршрутные пресеты, store (sqlite), gateway (OpenWrt), lifecycle, MCP,
   парсинг ссылок, обновления.
2. **Прокси-движок** (sing-box) — внешний движок, который делает собственно
   проксирование (VMess/VLESS/Trojan/Shadowsocks/Hysteria2/TUIC/REALITY/uTLS,
   TUN, DNS). В Go он подключён как библиотека `sagernet/sing-box`.

### Граница движка (`lavray-engine`)

`lavray-engine` — абстракция над прокси-движком (запуск/останов инстанса,
применение конфига, статистика, соединения). Реализации:

- **Этап 1 (текущий):** граница определена trait'ом `Engine`;管理层
  (presets/model/store/cfgbuild/links) полностью на Rust и тестируется без
  движка. Конфиг строится в формате sing-box (JSON) — совместимость с Go-ядром.
- **Этап 2 (план):** интеграция движка. Варианты (решение фиксируется отдельно):
  - Rust-нативные прокси-крейты (`shadowsocks-rust`, `tuic`, и др.) — покрытие
    протоколов растёт инкрементально;
  - либо FFI/ IPC к sing-box на переходный период.

  Выбор влияет на покрытие протоколов и фиксируется в ROADMAP до реализации
  `lavray-engine`. До этого момента Rust-ядро управляет конфигом и жизненным
  циклом, а сам прокси-трафик обеспечивает движок.

## Крейты и зависимости

```
lavray-core (bin)
  ├─ lavray-api        (ConnectRPC/gRPC сервисы)
  │    ├─ lavray-proto (prost/tonic типы из proto/lavray.proto)
  │    ├─ lavray-store (rusqlite)
  │    ├─ lavray-cfgbuild
  │    └─ lavray-engine
  ├─ lavray-cfgbuild   (конфиг sing-box: route/dns/in/outbounds)
  │    ├─ lavray-model
  │    ├─ lavray-presets
  │    └─ lavray-links
  ├─ lavray-store      (профили/подписки/настройки)
  │    └─ lavray-model
  ├─ lavray-links      (парсинг прокси-ссылок)
  │    └─ lavray-model
  ├─ lavray-presets    (preset.schema.v1, builtin)  ← готов
  └─ lavray-model      (Profile/Group/Settings/geo, canonjson)
```

Зависимости направлены вниз (без циклов): `model` и `presets` — листовые.

## Стандарты качества (паритет с Linux-сборкой)

- `clippy::pedantic` + `clippy::perf` = **0 предупреждений** (`-D warnings`).
  Обоснованные исключения — точечно, с комментарием (workspace `Cargo.toml`).
- `unsafe_code = forbid`.
- Всесторонние тесты на каждое изменение (явные + неявные сценарии), golden-тесты
  для cfgbuild (байт-в-байт стабильный JSON, как в Go).
- Трещотка размеров: новые файлы ≤ 200 строк, большие не растут.
- `cargo fmt` чист; CI на каждый push/PR.
- Суб-агент аудиты каждой волны: логика, код, работоспособность, perf,
  согласованность — рекурсия до нуля критичных/мажорных замечаний.
- release: `lto = thin`, `codegen-units = 1`, `strip = true`, `panic = abort`.

## Совместимость

- API-контракт — тот же `proto/lavray.proto` (12+ сервисов, ~80 RPC), что и у
  Go-ядра: оболочка (Tauri) и веб-панель работают без изменений.
- Формат пресетов — `preset.schema.v1` (байт-в-байт golden с Go).
- Конфиг движка — формат sing-box JSON.
- Протокол запуска `serve --listen-socket --data --token-file` и stdin-токены
  (master + agent) — паритет с Go `cmd/lavray-core`.
