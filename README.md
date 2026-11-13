# LAVRay Core (Rust)

[![CI](https://github.com/anatolijlaptev1991-ctrl/lavray-core-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/anatolijlaptev1991-ctrl/lavray-core-rs/actions/workflows/ci.yml)
![Rust](https://img.shields.io/badge/Rust-1.85%2B-orange?logo=rust)
![License](https://img.shields.io/badge/license-GPL--3.0-blue)

Перепись ядра [LAVRay](https://github.com/anatolijlaptev1991-ctrl/lavray)
(Go, `lavray/core`) на **Rust** — в отдельном репозитории, с теми же стандартами
качества, что и Linux-сборка оболочки.

> **Статус: поэтапная перепись в процессе.** Готов фундамент (`lavray-presets`).
> Полный план и текущее покрытие — [docs/ROADMAP.md](docs/ROADMAP.md).
> Архитектура и граница с прокси-движком — [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Стандарты качества (как в Linux-сборке)

- **clippy pedantic + perf = 0 предупреждений** (`-D warnings`), `cargo fmt` чист.
- **Всесторонние тесты** на каждое изменение (явные + неявные сценарии).
- **Трещотка размеров**: новые файлы ≤ 200 строк, большие не растут
  (`scripts/size_ratchet.py`).
- **CI**: fmt + clippy + тесты + release-сборка на каждый push/PR.
- **Суб-агент аудиты** каждой волны (логика, код, работоспособность, perf,
  согласованность) — рекурсия до нуля критичных/мажорных замечаний.
- `unsafe_code = forbid`, `panic = abort` + `strip` + LTO в release.

## Слои (crates/)

| Крейт | Назначение | Статус |
|-------|-----------|--------|
| `lavray-presets` | Маршрутные пресеты `preset.schema.v1`, валидация, 5 builtin | ✅ готов |
| `lavray-model` | Модели данных (Profile/Group/Settings/geo), canonjson | план |
| `lavray-links` | Парсинг прокси-ссылок (vmess/vless/trojan/ss/hy2/tuic) | план |
| `lavray-store` | Persistence (sqlite, rusqlite) | план |
| `lavray-cfgbuild` | Построение конфига sing-box (route/dns/in/outbounds) | план |
| `lavray-proto` | API-контракт (prost/tonic из `proto/lavray.proto`) | план |
| `lavray-engine` | Граница интеграции с прокси-движком | план |
| `lavray-api` | ConnectRPC/gRPC сервисы | план |
| `lavray-core` | Бинарь: lifecycle, stdin-протокол, сервер | план |

## Сборка и тесты

```bash
cargo test --workspace          # тесты
cargo clippy --all-targets -- -D warnings   # ноль предупреждений
cargo fmt --check               # форматирование
python scripts/size_ratchet.py  # трещотка размеров
cargo build --workspace --release
```

## Лицензия

[GPL-3.0](LICENSE) — производная nekoray и sing-box.
