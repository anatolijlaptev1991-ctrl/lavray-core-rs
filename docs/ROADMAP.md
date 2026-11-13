# ROADMAP — перепись ядра LAVRay на Rust

Поэтапный план. Каждая волна: реализация → всесторонние тесты → clippy
pedantic+perf=0 → суб-агент аудит → рекурсия до нуля → CI зелёный.
Объём Go-эталона: ~48k строк рукописного кода (без 21.5k generated).

## Волна 0 — фундамент репозитория ✅

- [x] Cargo workspace, edition 2021, rust-version 1.85.
- [x] Стандарты: clippy pedantic+perf deny, `unsafe_code = forbid`, fmt.
- [x] Трещотка размеров (`scripts/size_ratchet.py`, новые файлы ≤200).
- [x] CI: fmt + clippy + тесты + release-сборка.
- [x] Документация: README, ARCHITECTURE, ROADMAP.

## Волна 1 — lavray-presets ✅

- [x] `Preset/Routing/ProcessRule/DnsBlock` (паритет Go `presets`).
- [x] `Localized` — канонический JSON (ru/zh/en/es/de, детерминизм golden).
- [x] Валидация SCHEMA §4 (пути полей, анти-инъекция процессных правил).
- [x] 5 builtin-наборов (embed), lav-ru rev3.
- [x] 46 тестов, clippy 0, fmt.
- [x] Суб-агент аудит волны 1 (P1=0, P2→0: гард builtin, IgnoredAny; +16 тестов).

## Волна 2 — lavray-model ✅ (частично)

- [x] Profile (13 типов) + Detail (9 bean-структур), кастомный JSON detail по type.
- [x] Group/SubscriptionInfo/GroupKind, TestResult/TrafficCounters.
- [x] 14 тестов, clippy 0. VMess/Vless явный rename (snake_case → v_mess).
- [x] StreamSettings + Profile.stream (волна 2b), is_internal_full.
- [ ] Settings/geo, canonjson, dedupkey, customhash (остаток 2b).
- [ ] Суб-агент аудит волны 2.

## Волна 3 — lavray-links ✅ (парсинг)

- [x] Парсинг: vmess (base64 JSON + URL), vless/trojan, ss (SIP002 + v2rayN),
      hysteria2, tuic, socks/http. 25 тестов, clippy 0.
- [ ] Экспорт ссылок (BuildLink), QR-payload, nekoray/happ.
- [ ] Stream-настройки (ws/grpc/tls/reality), fuzz.
- [ ] Суб-агент аудит волны 3.

## Волна 4 — lavray-store ✅ (ядро)

- [x] sqlite (rusqlite): профили/группы/настройки, канонический JSON в `data`.
- [x] Миграции v1–v3 (идемпотентны), Default-группа (id 1_000_000_000), WAL/FK.
- [x] 11 тестов (CRUD, каскад, upsert настроек), clippy 0, трещотка 0.
- [ ] nekoimport (миграция NekoBox→LAVRay), подписки/latency/traffic CRUD.
- [ ] Суб-агент аудит волны 4.

## Волна 5 — lavray-cfgbuild ✅

- [x] Построение конфига sing-box: route/dns/inbounds/outbounds/tproxy.
- [x] Golden-тесты: 37/37 байт-в-байт с Go `cfgbuild/testdata` (serde_json
      BTreeMap → сортировка ключей MarshalIndent; ZERO-дефолты partial settings).
- [x] Пресеты → правила маршрутизации (rule-set .srs, dns_routing, процессные).
- [x] Allowlist-мерж custom_config (LNB-25), запрет путей к файлам (T-08).
- [x] 84 теста (37 golden + security/allowlist/units/validate), clippy 0.
- [ ] Суб-агент аудит волны 5.

## Волна 2b — model/presets достройка ✅ (частично)

- [x] StreamSettings (ws/grpc/tls/reality/mux/xhttp) + Profile.stream, round-trip.
- [x] is_internal_full; lenient unmarshal (serde default, паритет Go zero-values).
- [x] presets: parse/normalize_custom_rules, effective_process_rules (+тесты).
- [ ] Settings/geo, canonjson, dedupkey, customhash (остаток 2b).

## Волна 6 — lavray-proto + lavray-api

- [ ] prost/tonic типы из `proto/lavray.proto` (12+ сервисов, ~80 RPC).
- [ ] ConnectRPC/gRPC сервисы (Core/Profile/Subscription/Routing/Dns/Settings/
      Log/Stats/Connection/Diagnostics/Backup/Gateway/WebSession/Agent).
- [ ] Интеграционные тесты API.

## Волна 7 — lavray-engine + lavray-core

- [ ] Решение по движку (Rust-крейты vs FFI sing-box) — фиксируется до реализации.
- [ ] Граница `Engine`, lifecycle, stdin-протокол, сервер.
- [ ] gateway (OpenWrt tproxy/nftables), updates, MCP.
- [ ] Сквозные тесты с реальным движком.

## Критерии готовности ядра

- Все сервисы API реализованы и покрыты тестами (паритет proto).
- Конфиг-билдер даёт байт-в-байт golden с Go.
- Прокси-трафик работает (движок интегрирован, протоколы покрыты).
- clippy pedantic+perf=0, fmt, трещотка — на всех крейтах.
- Суб-агент аудиты всех волн — ноль критичных/мажорных.
- CI зелёный; релиз-бинарь совместим с оболочкой (тот же протокол запуска).
