package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"

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
		// Either exactly one mode is set, or none.
		flag.Usage()
		os.Exit(1)
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
		trans = transport.NewCompressedTransport(yandex.NewYandexDocsTransport(globalDocUrl, config))
	case "oneme":
		uidint, err := strconv.ParseInt(maxUid, 10, 64)
		if err != nil {
			log.Fatalf("Invalid --maxUid %q: %v", maxUid, err)
		}
		trans = transport.NewCompressedTransport(oneme.NewOneMeTransport(*exitNode, maxToken, uidint, config))
	default:
		log.Fatalf("Unknown transport type: %s", *transportType)
	}

	if err := trans.Start(); err != nil {
		log.Fatalf("Failed to start transport: %v", err)
	}

	tun, err := tunnel.NewTCPTunnel(trans, *exitNode)
	if err != nil {
		log.Fatalf("Failed to init tunnel: %v", err)
	}

	if *exitNode {
		log.Printf("Running as EXIT NODE (needs root for raw socket)")
		log.Printf("! Run: sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP")
		select {}
	} else {
		log.Printf("Running as CLIENT (SOCKS5 on %s)", *socksAddr)
		socks5Server := socks5.NewSOCKS5Server(*socksAddr, tun)
		log.Fatal(socks5Server.Start())
	}
}
