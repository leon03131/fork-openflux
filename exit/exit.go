// Package exit implements the v2 exit node: it accepts streams from the
// mux, dials the requested destination with the ordinary OS network stack
// (no root, no raw sockets, remote DNS resolution, IPv4/IPv6) and relays
// data with half-close propagation.
package exit

import (
	"context"
	"io"
	"net"
	"sync"
	"time"

	"github.com/leon03131/fork-openflux/mux"
	"github.com/leon03131/fork-openflux/utils"
	"github.com/leon03131/fork-openflux/wire"
)

type Server struct {
	mux    *mux.Mux
	dialer net.Dialer
}

func NewServer(m *mux.Mux) *Server {
	return &Server{
		mux:    m,
		dialer: net.Dialer{Timeout: 15 * time.Second},
	}
}

// Serve accepts streams until the mux is closed or ctx is cancelled.
func (s *Server) Serve(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		s.mux.Close()
	}()
	for {
		st, err := s.mux.Accept()
		if err != nil {
			return err
		}
		go s.handle(ctx, st)
	}
}

func (s *Server) handle(ctx context.Context, st *mux.Stream) {
	defer st.Close()

	addr := wire.JoinHostPort(st.DestHost(), st.DestPort())
	conn, err := s.dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		utils.Debugf("[EXIT] dial %s failed: %v", addr, err)
		st.RejectOpen(err.Error())
		return
	}
	defer conn.Close()

	if err := st.AcceptOpen(); err != nil {
		return
	}
	utils.Debugf("[EXIT] stream %d -> %s", st.ID(), addr)

	relay(conn, st)
}

// relay copies in both directions, propagating half-closes.
func relay(conn net.Conn, st *mux.Stream) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(conn, st)
		// Client finished sending: propagate EOF to the destination.
		if tc, ok := conn.(interface{ CloseWrite() error }); ok {
			tc.CloseWrite()
		} else {
			conn.Close()
		}
	}()

	go func() {
		defer wg.Done()
		io.Copy(st, conn)
		// Destination finished: propagate EOF to the client.
		st.CloseWrite()
	}()

	wg.Wait()
}
