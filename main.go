package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	_ "github.com/wlynxg/anet"

	"github.com/leon03131/fork-openflux/exit"
	"github.com/leon03131/fork-openflux/mux"
	"github.com/leon03131/fork-openflux/session"
	"github.com/leon03131/fork-openflux/socks5"
	"github.com/leon03131/fork-openflux/transport"
	"github.com/leon03131/fork-openflux/transport/oneme"
	"github.com/leon03131/fork-openflux/transport/onlyoffice"
	"github.com/leon03131/fork-openflux/transport/yandex"
	"github.com/leon03131/fork-openflux/tunnel"
	"github.com/leon03131/fork-openflux/utils"
)

// Version is the build version; release builds override it via
// -ldflags "-X main.Version=...".
var Version = "0.2.0-dev"

type cliConfig struct {
	client, exitNode    bool
	debug               bool
	socksAddr           string
	transportType, mode string
	docURL              string
	maxToken, maxUid    string
	addr, psk           string
}

func main() {
	fmt.Print("written by p1neappleXpress\n")
	if err := run(); err != nil {
		log.Printf("FATAL: %v", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `OpenFlux %s - TCP tunnel with pluggable transports

Usage:
  openflux client [flags]      Run as client (SOCKS5 proxy)
  openflux exit   [flags]      Run as exit node
  openflux doctor [flags]      Diagnose configuration and connectivity
  openflux version             Print version

Legacy flag style also works: openflux --client / --exit-node

Flags:
`, Version)
	flag.PrintDefaults()
}

func run() error {
	args := os.Args[1:]

	cmd := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd = args[0]
		args = args[1:]
	}

	var cfg cliConfig
	flag.BoolVar(&cfg.client, "client", false, "Run as client")
	flag.BoolVar(&cfg.exitNode, "exit-node", false, "Run as exit node")
	flag.BoolVar(&cfg.debug, "debug", false, "Enable verbose debug logging")
	flag.StringVar(&cfg.socksAddr, "socks5", "127.0.0.1:1080", "SOCKS5 listen address")
	flag.StringVar(&cfg.transportType, "transport", "yandex", "Transport type (yandex, onlyoffice, oneme, direct)")
	flag.StringVar(&cfg.mode, "mode", "v2", "Protocol mode (v2 = stream mux, legacy = gVisor packet tunnel)")
	flag.StringVar(&cfg.docURL, "url", "", "Document URL (yandex/onlyoffice transports)")
	flag.StringVar(&cfg.maxToken, "maxToken", "", "MAX Web token (oneme transport)")
	flag.StringVar(&cfg.maxUid, "maxUid", "", "MAX call user id (oneme transport)")
	flag.StringVar(&cfg.addr, "addr", "", "Address for direct transport (client: exit address; exit: listen address)")
	flag.StringVar(&cfg.psk, "psk", "", "Pre-shared key for v2 encryption (or env OPENFLUX_PSK)")
	insecure := flag.Bool("insecure", false, "Allow v2 without encryption (testing only)")
	flag.CommandLine.Usage = usage
	// NOTE: parse the sliced args, not os.Args, so subcommands work.
	if err := flag.CommandLine.Parse(args); err != nil {
		return err
	}
	if flag.NArg() > 0 {
		usage()
		return fmt.Errorf("unexpected arguments: %v", flag.Args())
	}

	switch cmd {
	case "version":
		fmt.Printf("OpenFlux %s\n", Version)
		return nil
	case "doctor":
		return runDoctor(&cfg)
	case "client":
		cfg.client = true
	case "exit":
		cfg.exitNode = true
	case "":
		// Legacy flag style.
	default:
		usage()
		return fmt.Errorf("unknown command %q", cmd)
	}

	if cfg.exitNode == cfg.client {
		usage()
		return fmt.Errorf("select exactly one mode: client or exit")
	}

	if cfg.debug {
		utils.EnableDebug()
	}

	if cfg.psk == "" {
		cfg.psk = os.Getenv("OPENFLUX_PSK")
	}
	if cfg.mode == "v2" && cfg.psk == "" && !*insecure {
		return fmt.Errorf("v2 requires --psk (or env OPENFLUX_PSK); pass --insecure to disable encryption")
	}
	if cfg.psk != "" {
		strong, err := validatePSK(cfg.psk)
		if err != nil {
			return err
		}
		cfg.psk = strong
	}

	log.Printf("=== OpenFlux %s ===", Version)
	log.Printf("Mode: %s", map[bool]string{true: "EXIT NODE", false: "CLIENT"}[cfg.exitNode])
	log.Printf("Transport: %s | Protocol: %s", cfg.transportType, cfg.mode)

	trans, err := buildTransport(&cfg)
	if err != nil {
		return err
	}

	// Graceful shutdown on SIGINT/SIGTERM.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if cfg.mode == "v2" {
		return runV2(ctx, trans, &cfg)
	}
	if cfg.mode != "legacy" {
		return fmt.Errorf("unknown mode %q (want v2 or legacy)", cfg.mode)
	}
	return runLegacy(ctx, trans, &cfg)
}

func buildTransport(cfg *cliConfig) (transport.Transport, error) {
	config := transport.DefaultConfig()
	var trans transport.Transport

	switch cfg.transportType {
	case "yandex":
		if cfg.docURL == "" {
			return nil, fmt.Errorf("--url is required for the yandex transport (Yandex Docs document URL)")
		}
		trans = yandex.NewYandexDocsTransport(cfg.docURL, config)
	case "onlyoffice":
		if cfg.docURL == "" {
			return nil, fmt.Errorf("--url is required for the onlyoffice transport (Yandex Disk document URL)")
		}
		trans = onlyoffice.NewOnlyOfficeTransport(cfg.docURL, config)
	case "oneme":
		uidint, err := strconv.ParseInt(cfg.maxUid, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid --maxUid %q: %w", cfg.maxUid, err)
		}
		trans = oneme.NewOneMeTransport(cfg.exitNode, cfg.maxToken, uidint, config)
	case "direct":
		if cfg.addr == "" {
			return nil, fmt.Errorf("--addr is required for the direct transport")
		}
		trans = transport.NewDirectTransport(cfg.addr, cfg.exitNode, config)
	default:
		return nil, fmt.Errorf("unknown transport type: %s", cfg.transportType)
	}

	// In v2 mode the raw carrier is used directly: stream DATA is mostly
	// TLS (incompressible), and session crypto defeats compression anyway.
	// Legacy packet mode keeps the LZ4 wrapper.
	if cfg.mode == "legacy" {
		trans = transport.NewCompressedTransport(trans)
	}
	return trans, nil
}

// validatePSK enforces PSK strength: only real 32-byte random keys in
// base64 or hex are accepted (Noise requires 256 bits of PSK entropy;
// human passphrases are not allowed as they are offline-bruteforceable).
func validatePSK(psk string) (string, error) {
	if b, err := hex.DecodeString(psk); err == nil && len(b) == 32 {
		return psk, nil // 32-byte hex key
	}
	if b, err := base64.StdEncoding.DecodeString(psk); err == nil && len(b) == 32 {
		return psk, nil // 32-byte base64 key
	}
	return "", fmt.Errorf("PSK must be a 32-byte random key in base64 or hex; generate one with `openssl rand -base64 32`")
}

// runLegacy runs the original gVisor packet tunnel (exit node needs root).
func runLegacy(ctx context.Context, trans transport.Transport, cfg *cliConfig) error {
	if cfg.exitNode && runtime.GOOS == "windows" {
		return fmt.Errorf("legacy exit node is unsupported on Windows (raw socket restrictions); use --mode v2")
	}
	if err := trans.Start(); err != nil {
		return fmt.Errorf("failed to start transport: %w", err)
	}

	tun, err := tunnel.NewTCPTunnel(trans, cfg.exitNode)
	if err != nil {
		trans.Stop() // do not leave the transport running after a failed init
		return fmt.Errorf("failed to init tunnel: %w", err)
	}

	if cfg.exitNode {
		log.Printf("Running as EXIT NODE (needs root for raw socket)")
		log.Printf("! Run: sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP")
		<-ctx.Done()
	} else {
		log.Printf("Running as CLIENT (SOCKS5 on %s)", cfg.socksAddr)
		socks5Server := socks5.NewSOCKS5Server(cfg.socksAddr, tun)
		errCh := make(chan error, 1)
		go func() { errCh <- socks5Server.Start() }()

		select {
		case err := <-errCh:
			tun.Close()
			trans.Stop()
			return err
		case <-ctx.Done():
			socks5Server.Close()
		}
	}

	log.Printf("Shutting down...")
	tun.Close()
	trans.Stop()
	return nil
}

// atomicDialer points SOCKS5 at the current mux; the pointer is swapped
// by the supervisor on every session rebuild.
type atomicDialer struct{ v atomic.Pointer[mux.Mux] }

func (d *atomicDialer) DialTCP(address string) (net.Conn, error) {
	m := d.v.Load()
	if m == nil {
		return nil, fmt.Errorf("no active session (carrier reconnecting)")
	}
	return m.DialTCP(address)
}

// runV2 runs the stream-mux protocol: SOCKS5 -> mux -> session -> carrier,
// and symmetrically on the exit side. No root/raw sockets required.
//
// A supervisor loop rebuilds the session whenever the carrier drops:
// existing streams die with the old session (they cannot survive a
// carrier reconnect), new connections use the fresh session.
func runV2(ctx context.Context, trans transport.Transport, cfg *cliConfig) error {
	if err := trans.Start(); err != nil {
		return fmt.Errorf("failed to start transport: %w", err)
	}
	defer trans.Stop()

	var socks5Server *socks5.SOCKS5Server
	var dialer *atomicDialer
	socksErrCh := make(chan error, 1)
	if !cfg.exitNode {
		dialer = &atomicDialer{}
		socks5Server = socks5.NewSOCKS5Server(cfg.socksAddr, dialer)
		go func() { socksErrCh <- socks5Server.Start() }()
		defer socks5Server.Close()
	}

	for ctx.Err() == nil {
		sess, err := session.New(trans, []byte(cfg.psk), !cfg.exitNode)
		if err != nil {
			return err
		}
		sess.Start()
		if err := sess.Handshake(); err != nil {
			sess.Close()
			log.Printf("handshake: %v (retrying)", err)
			select {
			case <-ctx.Done():
			case err := <-socksErrCh:
				return err
			case <-time.After(time.Second):
			}
			continue
		}
		log.Printf("v2 session established")

		if cfg.exitNode {
			if err := serveExitSession(ctx, sess); err != nil {
				return err
			}
			continue
		}

		m := mux.NewClientMux(sess)
		dialer.v.Store(m)
		select {
		case <-ctx.Done():
			m.Close()
		case <-sess.Closed():
			log.Printf("session lost (%v), waiting for carrier", sess.Err())
			// Point the dialer at nothing while rebuilding, so new
			// SOCKS5 connections get a clear "reconnecting" error
			// instead of hitting a dead mux.
			dialer.v.Store(nil)
			m.Close()
			// Give the next session a clean carrier channel.
			if b, ok := trans.(transport.Bouncer); ok {
				b.Bounce()
			}
		case err := <-socksErrCh:
			m.Close()
			return err
		}
	}

	log.Printf("Shutting down...")
	return nil
}

// serveExitSession serves one exit-side session until shutdown or session
// loss. Returns non-nil error only when the process should exit.
func serveExitSession(ctx context.Context, sess *session.Session) error {
	m := mux.NewServerMux(sess)
	defer m.Close()
	serveErr := make(chan error, 1)
	go func() { serveErr <- exit.NewServer(m).Serve(ctx) }()
	select {
	case <-ctx.Done():
		return nil
	case <-sess.Closed():
		log.Printf("session lost (%v), waiting for carrier", sess.Err())
		return nil
	case err := <-serveErr:
		// mux.ErrClosed here means the session died (or a GOAWAY
		// arrived): rebuild the session instead of dying.
		if err == nil || errors.Is(err, mux.ErrClosed) || sess.Err() != nil {
			return nil
		}
		return err
	}
}

// runDoctor validates the configuration and probes carrier connectivity.
func runDoctor(cfg *cliConfig) error {
	fmt.Printf("OpenFlux %s doctor\n", Version)
	fmt.Printf("carrier: %s\n", cfg.transportType)

	ok := true
	check := func(name string, err error) {
		if err != nil {
			ok = false
			fmt.Printf("  [FAIL] %s: %v\n", name, err)
		} else {
			fmt.Printf("  [ OK ] %s\n", name)
		}
	}

	flagMissing := func(format string, a ...interface{}) error {
		return fmt.Errorf(format, a...)
	}

	switch cfg.transportType {
	case "yandex":
		if cfg.docURL == "" {
			check("--url present", flagMissing("not set"))
			break
		}
		check("--url present", nil)
		if err := yandex.CheckDoc(cfg.docURL); err != nil {
			check("yandex doc config fetch", err)
			break
		}
		check("yandex doc config fetch", nil)
		check("yandex live websocket handshake", yandex.CheckLive(cfg.docURL))
	case "onlyoffice":
		if cfg.docURL == "" {
			check("--url present", flagMissing("not set"))
			break
		}
		check("--url present", nil)
		if err := onlyoffice.CheckDoc(cfg.docURL); err != nil {
			check("onlyoffice doc config fetch", err)
			break
		}
		check("onlyoffice doc config fetch", nil)
		check("onlyoffice live handshake", onlyoffice.CheckLive(cfg.docURL))
	case "oneme":
		if cfg.maxToken == "" {
			check("--maxToken present", flagMissing("not set"))
		} else {
			check("--maxToken present", nil)
		}
		if _, err := strconv.ParseInt(cfg.maxUid, 10, 64); err != nil {
			check("--maxUid valid", fmt.Errorf("%v", err))
		} else {
			check("--maxUid valid", nil)
		}
		if cfg.maxToken != "" {
			check("max websocket + login", oneme.Check(cfg.maxToken))
		}
	case "direct":
		if cfg.addr == "" {
			check("--addr present", flagMissing("not set"))
			break
		}
		check("--addr present", nil)
		conn, err := net.DialTimeout("tcp", cfg.addr, 3*time.Second)
		if err != nil {
			check(fmt.Sprintf("tcp dial %s (is the exit node running?)", cfg.addr), err)
		} else {
			conn.Close()
			check(fmt.Sprintf("tcp dial %s", cfg.addr), nil)
		}
	default:
		check("known transport", fmt.Errorf("unknown transport %q", cfg.transportType))
	}

	if !ok {
		return fmt.Errorf("doctor: checks failed")
	}
	fmt.Println("all checks passed")
	return nil
}
