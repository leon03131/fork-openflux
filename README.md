# OpenFlux

**English** | [Русский](README.ru.md)

*Original by [p1neappleXpress](https://github.com/p1neappleXpress/OpenFlux) · fork by [leon03131](https://github.com/leon03131/fork-openflux)*

Network stack research tool. TCP tunnel with pluggable transports.

## Overview
```
Client (SOCKS5) --> Transport --> Exit Node --> Internet
```

Client side runs a SOCKS5 proxy; the exit node decapsulates and forwards
traffic to the destination.

Transports (carriers):
1. **yandex** — packets via Yandex Docs cursor messages;
2. **oneme** — packets disguised as WebRTC ICE candidates over MAX call signaling;
3. **direct** — plain TCP reference carrier (local testing/debugging).

## Requirements
1. Golang v. 1.26.4+ - is required for building desktop client / exit node binary;
2. Android Native Development Kit (NDK) v.27.0.12077973+ - is required for building Android client binary;
3. XCode v. 26.6+ - is required for building iOS client binary;
4. Linux VPS / VDS exit node.

## Structure

```
├── main.go                 # CLI (client/exit/doctor/version), supervisor
├── wire/                   # Wire protocol v2 (binary framing)
├── session/                # Handshake (X25519+PSK), AEAD, keepalive
├── mux/                    # Stream multiplexer (net.Conn), flow control
├── exit/                   # v2 exit node (plain net.Dial, no root)
├── transport/
│   ├── transport.go        # Carrier interface
│   ├── memory.go           # In-process test carrier
│   ├── direct.go           # Reference TCP carrier
│   ├── compressor.go       # LZ4 wrapper (legacy mode)
│   ├── yandex/             # Yandex Docs carrier
│   └── oneme/              # MAX Messenger carrier
├── tunnel/                 # legacy gVisor packet tunnel
├── socks5/                 # SOCKS5 server
├── network/                # Checksums, packet parsing (legacy)
└── utils/                  # Debug logging
```

## Build (desktop client / exit-node binary)

```bash
go mod tidy
go build -o openflux .    # openflux.exe on Windows
```

## Build for Android (client binary)
```bash
export ANDROID_NDK_HOME=<your Android NDK path>
./build_android.sh
```

## Build for iOS (client binary)
```bash
export XCODE_PATH="<your Xcode.app path>" # optional, defaults to /Applications/Xcode.app
./build_ios.sh
```

## Usage

OpenFlux has two protocol modes:

- **v2 (default)** — stream multiplexer over an encrypted session. The exit
  node needs **no root** and no iptables rules; DNS is resolved on the exit
  side; IPv4/IPv6 supported.
- **legacy** (`--mode legacy`) — the original gVisor packet tunnel with raw
  sockets (exit node needs root; **Linux/macOS only** — Windows raw sockets
  are restricted by the OS; legacy also resolves DNS on the client side).

v2 **requires** a pre-shared key (`--psk` / `OPENFLUX_PSK`) — a 32-byte
random key in base64 or hex form. Generate one with `openssl rand -base64 32`.
Passphrases are rejected (they are offline-bruteforceable). The
`--insecure` flag disables encryption for local testing only.

### v2 quickstart (recommended)

Generate ONE key and copy it to both machines:
```bash
openssl rand -base64 32
# -> e.g. "kX7...=="
```

Exit node (any Linux box, no root):
```bash
export OPENFLUX_PSK='kX7...=='   # the SAME key on both sides
./openflux exit --transport yandex --url "YOUR_YANDEX_DOC_URL"
```

Client:
```bash
export OPENFLUX_PSK='kX7...=='   # identical value as on the exit node
./openflux client --transport yandex --url "YOUR_YANDEX_DOC_URL" --socks5 127.0.0.1:1080
```

Then point your browser's SOCKS5 proxy at `127.0.0.1:1080` (enable
"proxy DNS" / use SOCKS5h so domains resolve on the exit side).

For local testing without third-party services there is a reference
`direct` carrier (plain TCP):

```bash
./openflux exit   --transport direct --addr 0.0.0.0:9000 --psk "$OPENFLUX_PSK"
./openflux client --transport direct --addr EXIT_IP:9000 --psk "$OPENFLUX_PSK"
```

Diagnostics: `./openflux doctor --transport ... ` checks config and
connectivity. `./openflux version` prints the build version.

### legacy mode (exit node)

```bash
sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
sudo ./openflux exit --mode legacy --transport yandex --url "YOUR_YANDEX_DOC_URL"
```

### legacy mode (client)

```bash
./openflux client --mode legacy --transport yandex --url "YOUR_YANDEX_DOC_URL" --socks5 127.0.0.1:1080
```

## Flags

| Flag          | Default             | Description                |
|---------------|---------------------|----------------------------|
| `--client`    |                     | Run as client (or `client` subcommand)  |
| `--exit-node` |                     | Run as exit node (or `exit` subcommand) |
| `--mode`      | `v2`                | Protocol mode (v2, legacy)              |
| `--psk`       | env `OPENFLUX_PSK`  | Pre-shared key (v2 encryption)          |
| `--socks5`    | `127.0.0.1:1080`    | SOCKS5 listen address                   |
| `--url`       |                     | Document URL (yandex transport)         |
| `--maxToken`  | ``                  | MAX Web token (oneme transport)         |
| `--maxUid`    | ``                  | MAX call user id (oneme transport)      |
| `--addr`      | ``                  | Address (direct transport)              |
| `--debug`     | `false`             | Enable verbose logging                  |
| `--transport` | `yandex`            | Transport type (yandex, oneme, direct)  |

## Implementing custom transports

You are free to implement the `Transport` interface from `transport/transport.go` and register your custom transport in main.go switch block.

## License

This project is licensed under the **GNU General Public License v3.0 or later**.
See [LICENSE](LICENSE) for the full text.

Third-party licenses are listed in [NOTICE](NOTICE).

## Disclaimer

Educational use only. Test on your own machines and networks.

