# Эталонные app-cases (rust-anything) — Go sing-box 1.14.1-neko.1

Recorded behavior Go-эталона для переписи движка на Rust
(методология [rust-anything](https://github.com/erkamyaman/rust-anything),
шаг 3 «Record the whole app»). Запись — истина; Rust-порт обязан её повторять.

## Состав

| Путь | Что это |
|---|---|
| `etalon/gen_etalon_cases.py` | Генератор `inputs.jsonl`: 38 осознанных кейсов (check валидные/невалидные, format, rule-set match/compile, CLI-контракт). Каждый кейс перед записью прогоняется через эталон — расхождение ожиданий ломает генерацию. |
| `rust/app-cases/` | Запись поведения (trycmd): 230 кейсов = 38 осознанных + 192 семантические ловушки (юникод-argv и пр., все — error paths). `fs.sandbox`, кейсы самодостаточны. |
| `crates/lavray-cfgbuild/tests/testdata/golden/geo/*.srs` | Релизные .srs для golden-конфигов с rule-set (пути в конфигах относительные). Регенерация — см. ниже. |

## Воспроизведение

```sh
# 1) Собрать эталон из форка (однократно):
cd ../sing-box && go build -trimpath \
  -tags "with_gvisor,with_quic,with_dhcp,with_wireguard,with_utls,with_acme,with_clash_api,with_tailscale,with_ccm,with_ocm,with_cloudflared,with_usbip,with_openvpn,with_openconnect" \
  -o ../_deps/sing-box-etalon.exe ./etalon-main
# (etalon-main/main.go — обёртка package main над cmd/sing-box = boxmain)

# 2) Сгенерить кейсы и сверить ожидания:
python -I etalon/gen_etalon_cases.py   # 0 mismatched — обязано быть

# 3) Записать (перезапишет rust/app-cases, включая traps):
rust-anything app record . --name sing-box --inputs etalon/inputs.jsonl -- ../_deps/sing-box-etalon.exe

# 4) Верифицировать запись (эталон против себя = 100%):
rust-anything app replay .
```

Регенерация `golden/geo/*.srs` (из каталога `crates/lavray-cfgbuild/tests/testdata/golden`):

```sh
printf '{"version":3,"rules":[{"domain_suffix":["example.com"]}]}' > /tmp/s.json
printf '{"version":3,"rules":[{"ip_cidr":["10.0.0.0/8"]}]}'        > /tmp/i.json
for n in anthropic category-ads-all category-gov-ru category-ru cn \
         geolocation-\!cn google-deepmind google-gemini google openai \
         perplexity riot steam tld-cn twitter xai youtube; do
  ../_deps/../../../../../../_deps/sing-box-etalon.exe rule-set compile /tmp/s.json -o "geo/geosite/$n.srs"
done
for n in cn ru; do ...rule-set compile /tmp/i.json -o "geo/geoip/$n.srs"; done
```

## Как это защищает волны порта

- **7f rule engine / .srs**: кейсы `rs-match-*` — точные юнит-тесты матчера
  (hit → `match rules.[N]: …` в stdout, miss → пусто; **exit=0 в обоих случаях**);
  `rs-compile-domains` — бинарный формат .srs; `rs-format-source` — канонизация JSON.
- **Валидатор конфигов**: `check-*` фиксируют и вердикты, и тексты FATAL-ошибок
  (с ANSI-кодами — это часть контракта), включая неожиданности:
  пустой `{}` — **валиден**; битый uuid vmess и ссылка правила на несуществующий
  outbound **не ловятся** check-ем (runtime-only); ss-2022 ключ строго по длине метода.
- **Проверка порта**: `rust-anything app replay . --build "<наш бинарь lavray-core>"`
  после того, как волна 7f даст субкоманды `check`/`format`/`rule-set`.

## Границы

- Кейсы записаны на Windows (пути/тексты ОС в ошибках) — replay эталоном гонять
  на той же ОС, где записывали; в Linux-CI не включать (CI проверяет port иначе:
  golden cfgbuild + unit-тесты).
- Сетевые протоколы (REALITY, QUIC) app-cases не покрывают — там loopback-харнессы
  волн 7a–7e (`crates/lavray-engine` e2e) против Go-сервера.
