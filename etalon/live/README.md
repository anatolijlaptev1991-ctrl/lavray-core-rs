# etalon/live — живые Go-серверы для e2e тестов QUIC-протоколов

sing-box etalon 1.14.1-neko.1 (`../../_deps/sing-box-etalon.exe`) как
inbound-сервер: tuic (UDP 18443) и hysteria2 (UDP 18445), self-signed
сертификат, direct outbound. Лив-тесты
`cargo test -p lavray-engine --test tuic_hy2_live -- --ignored
--test-threads=1` прогоняют Rust-клиенты → Go-сервер → локальный TCP-echo.

## Поднятие

```bash
# 1. self-signed cert (не коммитится, в .gitignore)
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem \
  -days 3650 -nodes -subj "//CN=127.0.0.1"
# 2. TCP-echo-цель (питон, любой порт, тест делает свой эфемерный)
python -c "..."
# 3. серверы
sing-box-etalon.exe run -c tuic_server.json &
sing-box-etalon.exe run -c hy2_server.json &
```

Параметры пользователей — в `tuic_server.json` (uuid/password) и
`hy2_server.json` (password). Клиентские тесты используют те же значения
и `skip_verify` (self-signed).

## Отладочные заметки (найденные wire-баги)

- HTTP/3: имена заголовков — строго lowercase (RFC 9114 §4.2), иначе
  fork-quic-go сбрасывает поток H3 MessageError (0x10e);
- QPACK: literal-no-name-ref = `001` + huffman-бит 0x08 + 3-битный
  HPACK-varint префикс длины имени; header block начинается с
  RIC/DeltaBase (обе 0); клиент обязан открыть control + QPACK
  encoder/decoder uni-потоки;
- tuic v5: CommandConnect = 1 (iota в отдельном const-блоке), адрес
  перед портом (AddressSerializer без PortThenAddress);
- tuic EKM: label — сырые 16 байт uuid (не hex-строка);
- hy2: TCPResponse читается побайтово точно, иначе съедаются данные,
  приехавшие в одном QUIC-пакете с response.
