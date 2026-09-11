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
- `transport/yandex/`, `transport/oneme/`, `transport/onlyoffice/` — экспериментальные carrier'ы (сторонние сервисы, схема может сломаться; весь внешний ввод — недоверенный, никаких паникующих type assertions). `onlyoffice` — текущий редактор Яндекс.Документов для публичных ссылок (legacy `yandex` для них умер); курсорный канал поверх OnlyOffice Docs socket.io с обработкой waitAuth/unLockDocument (см. комментарии в onlyoffice.go).
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
