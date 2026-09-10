package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
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
	"github.com/leon03131/fork-openflux/transport/yandex"
	"github.com/leon03131/fork-openflux/tunnel"
	"github.com/leon03131/fork-openflux/utils"
)

var (
	globalDocUrl string
	maxToken     string
	maxUid       string
)

func main() {
	fmt.Print("written by p1neappleXpress\n")
	if err := run(); err != nil {
		log.Printf("FATAL: %v", err)
		os.Exit(1)
	}
}

func run() error {
	exitNode := flag.Bool("exit-node", false, "Run as exit node (needs root)")
	client := flag.Bool("client", false, "Run as client")
	debug := flag.Bool("debug", false, "Enable verbose debug logging")
	socksAddr := flag.String("socks5", "127.0.0.1:1080", "SOCKS5 listen address")
	transportType := flag.String("transport", "yandex", "Transport type (yandex, oneme, direct)")
	mode := flag.String("mode", "v2", "Protocol mode (v2 = stream mux, legacy = gVisor packet tunnel)")
	flag.StringVar(&globalDocUrl, "url", "http://#", "Document URL (Yandex Docs transport)")
	flag.StringVar(&maxToken, "maxToken", "", "MAX Web token (oneme transport)")
	flag.StringVar(&maxUid, "maxUid", "", "MAX call user id (oneme transport)")
	addr := flag.String("addr", "", "Address for the direct transport (client: exit address; exit: listen address)")
	flag.Parse()

	if *exitNode == *client {
		// Exactly one mode must be selected.
		flag.Usage()
		return fmt.Errorf("select exactly one of --client or --exit-node")
	}

	if *debug {
		utils.EnableDebug()
	}

	log.Printf("=== OpenFlux ===")
	log.Printf("Mode: %s", map[bool]string{true: "EXIT NODE", false: "CLIENT"}[*exitNode])
	log.Printf("Transport: %s | Protocol: %s", *transportType, *mode)

	config := transport.DefaultConfig()
	var trans transport.Transport

	// In v2 mode the raw carrier is used directly: stream DATA is mostly
	// TLS (incompressible), and stage-7 crypto would defeat compression
	// anyway. Legacy packet mode keeps the LZ4 wrapper.
	compress := *mode == "legacy"
	switch *transportType {
	case "yandex":
		if globalDocUrl == "" || globalDocUrl == "http://#" {
			return fmt.Errorf("--url is required for the yandex transport (Yandex Docs document URL)")
		}
		trans = yandex.NewYandexDocsTransport(globalDocUrl, config)
	case "oneme":
		uidint, err := strconv.ParseInt(maxUid, 10, 64)
		if err != nil {
			return fmt.Errorf("invalid --maxUid %q: %w", maxUid, err)
		}
		trans = oneme.NewOneMeTransport(*exitNode, maxToken, uidint, config)
	case "direct":
		if *addr == "" {
			return fmt.Errorf("--addr is required for the direct transport")
		}
		trans = transport.NewDirectTransport(*addr, *exitNode, config)
	default:
		return fmt.Errorf("unknown transport type: %s", *transportType)
	}
	if compress {
		trans = transport.NewCompressedTransport(trans)
	}

	// Graceful shutdown on SIGINT/SIGTERM.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if *mode == "v2" {
		return runV2(ctx, trans, *exitNode, *socksAddr)
	}
	if *mode != "legacy" {
		return fmt.Errorf("unknown mode %q (want v2 or legacy)", *mode)
	}

	if err := trans.Start(); err != nil {
		return fmt.Errorf("failed to start transport: %w", err)
	}

	tun, err := tunnel.NewTCPTunnel(trans, *exitNode)
	if err != nil {
		trans.Stop() // do not leave the transport running after a failed init
		return fmt.Errorf("failed to init tunnel: %w", err)
	}

	if *exitNode {
		log.Printf("Running as EXIT NODE (needs root for raw socket)")
		log.Printf("! Run: sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP")
		<-ctx.Done()
	} else {
		log.Printf("Running as CLIENT (SOCKS5 on %s)", *socksAddr)
		socks5Server := socks5.NewSOCKS5Server(*socksAddr, tun)
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
func runV2(ctx context.Context, trans transport.Transport, exitNode bool, socksAddr string) error {
	if err := trans.Start(); err != nil {
		return fmt.Errorf("failed to start transport: %w", err)
	}
	defer trans.Stop()

	var socks5Server *socks5.SOCKS5Server
	var dialer *atomicDialer
	socksErrCh := make(chan error, 1)
	if !exitNode {
		dialer = &atomicDialer{}
		socks5Server = socks5.NewSOCKS5Server(socksAddr, dialer)
		go func() { socksErrCh <- socks5Server.Start() }()
		defer socks5Server.Close()
	}

	for ctx.Err() == nil {
		sess := session.New(trans)
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

		if exitNode {
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
			m.Close()
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
		return err
	}
}
