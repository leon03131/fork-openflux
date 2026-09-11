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
	mux       *mux.Mux
	dialer    net.Dialer
	watchOnce sync.Once
}

func NewServer(m *mux.Mux) *Server {
	return &Server{
		mux: m,
		// Deliberately smaller than mux.OpenTimeout (25s): the client
		// must get OPEN_ERROR, not a timeout, on slow destinations.
		dialer: net.Dialer{Timeout: 10 * time.Second},
	}
}

// Serve accepts streams until the mux is closed or ctx is cancelled.
// The ctx watcher is registered once per Server, not per call, so
// repeated Serve calls (session rebuilds) do not leak goroutines.
func (s *Server) Serve(ctx context.Context) error {
	s.watchOnce.Do(func() {
		go func() {
			<-ctx.Done()
			s.mux.Close()
		}()
	})
	for {
		st, err := s.mux.Accept()
		if err != nil {
			// Mux closed during graceful shutdown is not an error.
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go s.handle(ctx, st)
	}
}

func (s *Server) handle(ctx context.Context, st *mux.Stream) {
	defer st.Close()

	// The peer may have closed the stream while it sat in acceptCh.
	if st.IsClosed() {
		return
	}

	addr := wire.JoinHostPort(st.DestHost(), st.DestPort())
	// Cancel the dial if the stream dies mid-connect (CLOSE raced OPEN).
	dialCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		select {
		case <-st.Done():
			cancel()
		case <-dialCtx.Done():
		}
	}()
	conn, err := s.dialer.DialContext(dialCtx, "tcp", addr)
	if err != nil {
		utils.Debugf("[EXIT] dial %s failed: %v", addr, err)
		// Do not leak internal dial errors (they map the exit's
		// network); the client only needs to know it failed.
		st.RejectOpen("dial failed")
		return
	}
	defer conn.Close()

	if err := st.AcceptOpen(); err != nil {
		return
	}
	utils.Debugf("[EXIT] stream %d -> %s", st.ID(), addr)

	relay(conn, st)
}

// relay copies in both directions with true TCP half-close semantics:
// HALF_CLOSE never kills the opposite direction (a server may think for
// a long time before answering). If the stream dies (session lost,
// peer CLOSE), the destination connection is force-closed so both copy
// goroutines terminate and the FD is released.
func relay(conn net.Conn, st *mux.Stream) {
	var wg sync.WaitGroup
	wg.Add(2)
	done := make(chan struct{})

	go func() {
		select {
		case <-st.Done():
			conn.Close() // unblock both io.Copies
		case <-done:
		}
	}()

	go func() {
		defer wg.Done()
		io.Copy(conn, st)
		// Client finished sending: propagate EOF to the destination.
		if tc, ok := conn.(interface{ CloseWrite() error }); ok {
			tc.CloseWrite()
		}
	}()

	go func() {
		defer wg.Done()
		io.Copy(st, conn)
		// Destination finished: propagate EOF to the client.
		st.CloseWrite()
	}()

	wg.Wait()
	close(done)
}
