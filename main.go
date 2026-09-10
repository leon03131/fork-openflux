package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	_ "github.com/wlynxg/anet"

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
	transportType := flag.String("transport", "yandex", "Transport type (yandex, oneme)")
	flag.StringVar(&globalDocUrl, "url", "http://#", "Document URL (Yandex Docs transport)")
	flag.StringVar(&maxToken, "maxToken", "", "MAX Web token (oneme transport)")
	flag.StringVar(&maxUid, "maxUid", "", "MAX call user id (oneme transport)")
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
	log.Printf("Transport: %s", *transportType)

	config := transport.DefaultConfig()
	var trans transport.Transport

	switch *transportType {
	case "yandex":
		if globalDocUrl == "" || globalDocUrl == "http://#" {
			return fmt.Errorf("--url is required for the yandex transport (Yandex Docs document URL)")
		}
		trans = transport.NewCompressedTransport(yandex.NewYandexDocsTransport(globalDocUrl, config))
	case "oneme":
		uidint, err := strconv.ParseInt(maxUid, 10, 64)
		if err != nil {
			return fmt.Errorf("invalid --maxUid %q: %w", maxUid, err)
		}
		trans = transport.NewCompressedTransport(oneme.NewOneMeTransport(*exitNode, maxToken, uidint, config))
	default:
		return fmt.Errorf("unknown transport type: %s", *transportType)
	}

	if err := trans.Start(); err != nil {
		return fmt.Errorf("failed to start transport: %w", err)
	}

	tun, err := tunnel.NewTCPTunnel(trans, *exitNode)
	if err != nil {
		trans.Stop() // do not leave the transport running after a failed init
		return fmt.Errorf("failed to init tunnel: %w", err)
	}

	// Graceful shutdown on SIGINT/SIGTERM.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

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
