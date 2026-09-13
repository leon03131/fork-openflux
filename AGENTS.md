# AGENTS.md — OpenFlux (fork: leon03131/fork-openflux)

## Что это

Приватный форк [p1neappleXpress/OpenFlux](https://github.com/p1neappleXpress/OpenFlux) с глубокой переработкой: TCP-туннель с подключаемыми carrier'ами. Оригинал доступен как git remote `upstream`.

## Архитектура (v2, основная)

```
Client:  SOCKS5 -> mux (streams) -> session (wire frames + AEAD) -> carrier
Exit:    carrier -> session -> mux -> net.DialContext (NO root needed)
```

Пакеты:
- `wire/` — бинарный фрейминг v2 (magic/version/type/streamID/len). Fuzz-тесты обязательны для изменений.
- `session/` — handshake (HELLO с X25519+PSK), AEAD (ChaCha20-Poly1305, случайный nonce на сообщение), keepalive, watchdog. НЕ управляет жизнью транспорта.
- `mux/` — стримы net.Conn поверх сессии. Credit-based flow control (512 KiB/стрим), half-close. Client = нечётные stream ID, exit = чётные.
- `exit/` — exit-нода v2: Accept → DialContext → relay с half-close.
- `transport/` — Carrier-интерфейс (`Transport`), MemoryTransport (тесты), DirectTransport (reference, plain TCP), CompressedTransport (LZ4, только legacy).
- `transport/reliable/` — reliability-адаптер поверх lossy carrier'а: selective-repeat ARQ (новый кадр уходит один раз немедленно; fast retransmit СЕЛЕКТИВНЫЙ по SACK-bitmap — пересылаются только кадры, доказанно потерянные: 3+ более поздних seq за-SACK-аны (RFC 9002 packet threshold), плюс порог 3 dup-ack с re-arm каждые 8, fallback на голову дыры при пустом bitmap — и RTO = max(500мс, 2×srtt) с экспоненциальным backoff, полное окно одним сообщением; cumulative ackThrough + 64-bit SACK bitmap (ackBits), epoch на поколение, `NewGeneration()` при rebuild сессии), строгий FIFO наверх. Формат OFR2: channelID (HKDF из PSK, изоляция пар на общем документе) + ackThrough + ackBits + HMAC-SHA256(16) метаданных + CRC32. Bounds: 256 кадров / min(2 MiB, бюджет окна в inner.MaxPayload) unacked — wire-учёт (12B+payload на кадр), backpressure в Send. Send-контракт: принятый в окно кадр не возвращает inner-ошибки наружу (retransmit лечит), IsConnected игнорирует transient-reconnect carrier'а. Observability: atomic-счётчики (Dropped/TransmitErrors/Retransmits/AckProgress) + Debugf-пульс каждые 10с при активности. Регресс wire-overhead: TestNoQuadraticBlowup (до: snapshot-подход давал N×окно на проводе). Детали — в doc-comment пакета.
- `transport/yandex/`, `transport/oneme/`, `transport/onlyoffice/`, `transport/volga/`, `transport/mail/` — экспериментальные carrier'ы (сторонние сервисы, схема может сломаться; весь внешний ввод — недоверенный, никаких паникующих type assertions). `onlyoffice` — текущий редактор Яндекс.Документов для публичных ссылок (legacy `yandex` для них умер); курсорный канал поверх OnlyOffice Docs socket.io с обработкой waitAuth/unLockDocument (см. комментарии в onlyoffice.go). `mail` — тот же курсорный канал поверх Р7-Офиса (форк OnlyOffice) в Mail.ru Облаке: конфиг через POST `/api/v4/r7/edit` (поле `public` = путь ссылки без `/public`), JWT в `jwtOpen`, waitAuth/unLockDocument как в onlyoffice. `volga` — новый редактор Яндекс.Документов (Volga): auth через `officeActionData.action_url` → relay POST `volga.yandex.ru/session/main/<rp>/relay` (bundle: 2 cover-опы + base64 blob с OFX1-маркером) + приём через xiva push websocket (`push.yandex.ru/v2/subscribe`), re-authorize по 401/403; cover-опы вставляют «A» в документ — использовать выделенный документ.
- `tunnel/`, `socks5/`, `network/` — legacy packet mode (gVisor + raw sockets) и SOCKS5-сервер (используется обоими режимами через интерфейс Dialer).

Legacy-режим (`--mode legacy`) — исходный packet-tunnel через gVisor; v2 (`--mode v2`, дефолт) — stream-mux. Не удалять legacy без отдельного решения.

## Жёсткие правила

1. **Внешний ввод недоверен**: парсеры — bounded, только comma-ok assertions, fuzz-тесты. Паника на вводе = критический баг.
2. **Ошибки Send/Connect/Login не проглатывать** — транспорт обязан возвращать ошибку, а не молча дропать.
3. **Библиотеки не вызывают os.Exit/log.Fatal** — только main.
4. **Никаких PII/токенов в логах** (см. redactEndpointToken).
5. Секреты только через `--psk` или env `OPENFLUX_PSK`.
6. После изменений: `gofmt -w .`, `go vet ./...`, `go test ./...`, кросс-билд `GOOS=linux/darwin go build ./...` — всё зелёное до коммита.
7. Один этап = один коммит. Не мешать рефакторинг с фичами.
8. `go test -race` локально не работает (нет gcc на Windows) — гонять в CI (Linux job).

## Сборка и тесты

```powershell
# Go живёт в O:\Go\bin (не в PATH у всех сессий)
go build -o openflux.exe .
go test ./...
GOOS=linux go build ./...      # кросс-проверка
go test -bench . ./...         # бенчмарки (через cmd /c, PowerShell ломает -bench=.)
```

Android: `./build_android.sh` (нужен NDK, `-checklinkname=0` для anet). iOS: `./build_ios.sh` (Xcode).

## Живой smoke-тест (Windows)

```powershell
# PSK: 32 случайных байта в base64 (openssl rand -base64 32). Для локального
# smoke-теста можно --insecure без ключа.
# Exit:   openflux.exe exit --transport direct --addr 127.0.0.1:9000 --insecure
# Client: openflux.exe client --transport direct --addr 127.0.0.1:9000 --socks5 127.0.0.1:1080 --insecure
# Проверка: curl.exe --socks5-hostname 127.0.0.1:1080 http://example.com/
```

## Стиль коммитов

Короткое summary в императиве + детали через двоеточие. Примеры в `git log`.
