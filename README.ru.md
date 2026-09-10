# OpenFlux

[English](README.md) | **Русский**

Исследовательский инструмент сетевого стека. TCP-туннель с подключаемыми транспортами.

## Обзор
```
Client (SOCKS5) --> Transport --> Exit Node --> Internet
```

## Требования
1. Golang v. 1.26.4+ — требуется для сборки бинарника десктопного клиента / выходной ноды;
2. Android Native Development Kit (NDK) v.27.0.12077973+ — требуется для сборки бинарника для Android-клиента;
3. XCode v. 26.6+ — требуется для сборки бинарника для iOS-клиента;
4. VPS / VDS выходная нода на Linux.

## Обзор

TCP-пакеты передаются через Transport. На данный момент доступны два транспорта:
1. Yandex — отправляет пакеты через курсорные сообщения Yandex Docs;
2. Max — отправляет пакеты, замаскированные под WebRTC ICE-кандидаты, через сигнальный канал звонка MAX.

Клиентская часть запускает SOCKS5-прокси, выходная нода декапсулирует и пересылает пакеты в пункт назначения.

## Структура

```
├── main.go                 # CLI (client/exit/doctor/version), супервизор
├── wire/                   # Wire-протокол v2 (бинарный фрейминг)
├── session/                # Рукопожатие (X25519+PSK), AEAD, keepalive
├── mux/                    # Потоковый мультиплексор (net.Conn), flow control
├── exit/                   # v2 выходная нода (net.Dial, root не нужен)
├── transport/
│   ├── transport.go        # Интерфейс Carrier
│   ├── memory.go           # In-process тестовый carrier
│   ├── direct.go           # Эталонный TCP carrier
│   ├── compressor.go       # LZ4-обёртка (legacy-режим)
│   ├── yandex/             # Yandex Docs carrier
│   └── oneme/              # MAX Messenger carrier
├── tunnel/                 # legacy gVisor packet-туннель
├── socks5/                 # SOCKS5-сервер
├── network/                # Чексуммы, парсинг пакетов (legacy)
└── utils/                  # Отладочное логирование
```

## Сборка (бинарник десктоп-клиента / выходной ноды)

```bash
go mod tidy
go build -o universal-bypass-tool .
```

## Сборка для Android (клиентский бинарник)
```bash
export ANDROID_NDK_HOME=<путь до вашего Android NDK>
./build_android.sh
```

## Сборка для iOS (клиентский бинарник)
```bash
export XCODE_PATH="<путь до вашего Xcode.app>" # опционально, по умолчанию /Applications/Xcode.app
./build_ios.sh
```

## Использование

У OpenFlux два режима протокола:

- **v2 (по умолчанию)** — потоковый мультиплексор поверх зашифрованной
  сессии. Выходной ноде **не нужен root** и правила iptables; DNS
  резолвится на стороне ноды; поддерживаются IPv4/IPv6.
- **legacy** (`--mode legacy`) — исходный gVisor packet-туннель с
  raw-сокетами (ноде нужен root).

### Быстрый старт v2 (рекомендуется)

Выходная нода (любой Linux, без root):
```bash
export OPENFLUX_PSK="your-long-random-shared-secret"
./openflux exit --transport yandex --url "YOUR_YANDEX_DOC_URL"
```

Клиент:
```bash
export OPENFLUX_PSK="your-long-random-shared-secret"
./openflux client --transport yandex --url "YOUR_YANDEX_DOC_URL" --socks5 127.0.0.1:1080
```

Затем настройте SOCKS5-прокси в браузере на `127.0.0.1:1080` (включите
«проксировать DNS» / SOCKS5h, чтобы домены резолвились на стороне ноды).

Для локального тестирования без сторонних сервисов есть эталонный
carrier `direct` (чистый TCP):

```bash
./openflux exit   --transport direct --addr 0.0.0.0:9000 --psk secret
./openflux client --transport direct --addr EXIT_IP:9000 --psk secret
```

Диагностика: `./openflux doctor --transport ...` — проверка конфигурации
и связности. `./openflux version` — версия сборки.

### legacy-режим (выходная нода)

```bash
sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
sudo ./openflux exit --mode legacy --transport yandex --url "YOUR_YANDEX_DOC_URL"
```

### legacy-режим (клиент)

```bash
./openflux client --mode legacy --transport yandex --url "YOUR_YANDEX_DOC_URL" --socks5 127.0.0.1:1080
```

## Флаги

| Флаг          | По умолчанию        | Описание                                |
|---------------|---------------------|-----------------------------------------|
| `--client`    |                     | Режим клиента (или сабкоманда `client`) |
| `--exit-node` |                     | Режим ноды (или сабкоманда `exit`)      |
| `--mode`      | `v2`                | Режим протокола (v2, legacy)            |
| `--psk`       | env `OPENFLUX_PSK`  | Общий секрет (шифрование v2)            |
| `--socks5`    | `127.0.0.1:1080`    | Адрес SOCKS5 прокси                     |
| `--url`       |                     | URL документа (транспорт yandex)        |
| `--maxToken`  | ``                  | MAX Web токен (транспорт oneme)         |
| `--maxUid`    | ``                  | ID пользователя для звонка (oneme)      |
| `--addr`      | ``                  | Адрес (транспорт direct)                |
| `--debug`     | `false`             | Включить подробное логирование          |
| `--transport` | `yandex`            | Тип транспорта (yandex, oneme, direct)  |

## Реализация собственных транспортов

Вы можете реализовать интерфейс `Transport` из `transport/transport.go` и зарегистрировать свой транспорт в switch-блоке в main.go.

## Лицензия

Проект распространяется под лицензией **GNU General Public License v3.0 or later**.
Полный текст — в файле [LICENSE](LICENSE).

Лицензии третьих сторон — в файле [NOTICE](NOTICE).

## Дисклеймер

Только для образовательного использования. Тестируйте на собственных машинах и сетях.
