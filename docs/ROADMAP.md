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

## Волна 6 — lavray-proto + lavray-api (идёт)

- [x] prost/tonic типы из `proto/lavray.proto` (15 сервисов, 97 RPC).
- [x] SettingsService (каталог, get/set/reset, aggregated-флаги перезапуска).
- [x] ProfileService (CRUD/Import/Export/groups, конверсии model↔proto).
- [x] RoutingService (18.11): List/Get/Create/Update/Delete/Reset/Activate/
      GetActive/Export/Import; repo на meta `routing.custom_presets`
      (DATA_LOSS на повреждение), plan_insert (mint custom:<slug>),
      активный в settings `routing.active_preset` (F2 аудита №7), удаление
      активного → «global» + снятие DNS-карточки, конфликт ревизий ABORTED.
- [x] Волна 6.5: конвертер маршрутов NekoRay 4.x (порт Go convert.go),
      DnsService (GetDns/SetDns карточки T-31 + ValidateDnsJson FR-UI-149).
- [ ] Переопределения builtin (<данные>/presets/override, T-75/7.5).
- [ ] Остальные сервисы (Core/Subscription/Log/Stats/Connection/
      Diagnostics/Backup/Gateway/WebSession/Agent) — по мере движка (волна 7).
- [x] Интеграционные тесты API (347 всего; RoutingService — 15).

## Волна 7 — lavray-engine + lavray-core (РЕШЕНО 18.11: полный Rust-движок)

Владелец выбрал полный перепись движка на Rust — без Go sing-box (ни child,
ни FFI). Порядок волн (каждая = работающий инкремент со сквозными тестами):

- [x] 7a: Engine-каркас + mixed-инбаунд (SOCKS5/HTTP CONNECT) + outbound
      direct + прокси-цикл — первый сквозной трафик через Rust.
- [x] 7b: shadowsocks AEAD-2022 (клиент + тестовый сервер, e2e loopback).
- [x] 7c: trojan (rustls) + vmess (AEAD, alterId=0, паритет sing-vmess v0.2.8).
- [x] 7d: vless v0 (REALITY — в 7f-цикле).
- [x] 7e: WebSocket-транспорт RFC 6455 (клиент + сервер).
- [x] 7f-1: крейт lavray-rules — headless rule-set source v3: строгий парсер
      (unknown-field в Go-формате), item'ы в порядке Go, Go-описания
      (`domain=[a b c...]`), матчер (bare/dotted suffix, lowercase, regex,
      ip_cidr; logical and/or + invert). Субкоманда `lavray-core rule-set
      match` — replay 9/9 rs-match кейсов БАЙТ-В-БАЙТ с записью эталона.
      17 тестов (recorded-семантика: bare-суффикс = exact|dot-suffix,
      dotted = только dot-suffix, process/port в CLI не матчатся, exit=0
      при промахе, вывод в stderr).
- [x] 7f-2a: бинарные .srs (v1–v5 reader): succinct set (побитовые
      rank/select), IPSet-диапазоны, varbin; `rule-set match -f binary` —
      стресс 8k-доменов и все 19 golden .srs IDENTICAL с эталоном.
- [x] 7f-2b: субкоманды `check`/`format`/`rule-set format|compile` —
      replay 227/227 порта против записи эталона байт-в-байт (Go-тексты
      ошибок encoding/json, cobra help/флаги, Listable-синглтоны,
      ANSI-FATAL, [CWD]-нормализация); .srs writer (round-trip через
      эталон); крейт lavray-sbconfig; perf: Criterion bench, exact →
      HashSet, суффиксы → succinct trie, keyword/regex → RegexSet,
      IpRanges → сортировка+partition_point (hit 44µs → 0.68µs, 65×).
- [x] 7f-3a: AdGuard-матчер (||x^, |x^, *-подстановки, рекурсия 100) +
      logical binary-правила (and/or/invert, подправила с полными
      item'ами) — живое сравнение с эталоном 32/32 IDENTICAL
      (большой+adguard+logical+golden наборы).
- [x] 7f-3b: downgrade-семантика compile (v5→4→3→2 по наличию v3-полей,
      паритет версий байта проверен живьём: v3nt=3, v3d=2, big=2);
      network_type/u8-InterfaceType + nil-NetworkManager семантика
      (пустое правило матчит ВСЁ, rule_abstract len==0 → true) —
      ПОЛНЫЙ live-паритет 114/114 по всем наборам.
- [x] 7f-3c-1: крейт lavray-dns — wire-format RFC 1035 (parse/build,
      сжатие-указатели), UDP-транспорт, DoH (rustls + HTTP/1.1, chunked),
      FakeIP-пул (детерминированный, wrap-on-exhaust); живые e2e
      (Cloudflare UDP + Google DoH — 2/2, #[ignore] в CI); 13 тестов.
- [ ] 7f-3c-2: TUN (порт netstack); REALITY (TLS1.3 ClientHello-
      мимикрия); QUIC: hysteria2, tuic (quinn); DoT; CLI-кейсы cobra
      (version/help/unknown) — байт-паритет.
- [x] 7g (MVP): бинарь `lavray-core serve` (паритет запуска Go) + API-интеграция.
- [ ] gateway (OpenWrt tproxy/nftables), updates, MCP.
- [ ] Сквозные тесты с реальным движком (в т.ч. против эталонных серверов).

## Эталон recorded behavior (rust-anything, 19.11)

Установлен `rust-anything` v1.5.1 (CLI + MCP + скилл у агентов); Go-эталон
sing-box 1.14.1-neko.1 собирается обёрткой `../sing-box/etalon-main`
(полные релизные теги). `rust/app-cases/` — 230 trycmd-кейсов (38 осознанных +
192 ловушек), запись верифицирована `app replay` 230/230. Процесс и границы —
`etalon/README.md`. Кейсы `check-*`/`rs-*` — приёмочный набор волны 7f;
все 37 golden cfgbuild подтверждены эталонным `check` (29 сразу + 8 после
генерации `golden/geo/*.srs`).

## Критерии готовности ядра

- Все сервисы API реализованы и покрыты тестами (паритет proto).
- Конфиг-билдер даёт байт-в-байт golden с Go.
- Прокси-трафик работает (движок интегрирован, протоколы покрыты).
- clippy pedantic+perf=0, fmt, трещотка — на всех крейтах.
- Суб-агент аудиты всех волн — ноль критичных/мажорных.
- CI зелёный; релиз-бинарь совместим с оболочкой (тот же протокол запуска).
