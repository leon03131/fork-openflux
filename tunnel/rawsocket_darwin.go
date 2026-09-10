package tunnel

import (
	"fmt"
	"syscall"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"

	"github.com/leon03131/fork-openflux/utils"
)

// RawSocketEndpoint is the exit-node internet-facing link endpoint.
// macOS implementation; shared logic lives in rawsocket_common.go.
type RawSocketEndpoint struct {
	*rawSocketState
	sendFd int
	recvFd int
}

func NewRawSocketEndpoint(nicID tcpip.NICID, localIP [4]byte) (*RawSocketEndpoint, error) {
	sendFd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return nil, fmt.Errorf("send socket failed: %v (need root)", err)
	}

	if err := syscall.SetsockoptInt(sendFd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		syscall.Close(sendFd)
		return nil, fmt.Errorf("IP_HDRINCL: %v", err)
	}

	recvFd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		syscall.Close(sendFd)
		return nil, fmt.Errorf("recv socket failed: %v (need root)", err)
	}

	addr := &syscall.SockaddrInet4{
		Addr: [4]byte{0, 0, 0, 0},
		Port: 0,
	}
	if err := syscall.Bind(recvFd, addr); err != nil {
		syscall.Close(sendFd)
		syscall.Close(recvFd)
		return nil, fmt.Errorf("bind failed: %v", err)
	}

	ep := &RawSocketEndpoint{
		rawSocketState: newRawSocketState(nicID, localIP),
		sendFd:         sendFd,
		recvFd:         recvFd,
	}

	go ep.readLoop()
	return ep, nil
}

func (e *RawSocketEndpoint) readLoop() {
	buf := make([]byte, 65535)

	for {
		n, _, err := syscall.Recvfrom(e.recvFd, buf, 0)
		if err != nil {
			if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
				time.Sleep(10 * time.Millisecond)
				continue
			}
			utils.Debugf("[RAW-NIC%d] Read error: %v", e.nicID, err)
			return
		}
		e.handleIncomingPacket(buf, n)
	}
}

func (e *RawSocketEndpoint) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	n := 0
	for _, pkt := range pkts.AsSlice() {
		data, dst, ok := e.prepareOutgoing(pkt.ToView().ToSlice())
		if !ok {
			continue
		}

		addr := &syscall.SockaddrInet4{
			Addr: dst,
			Port: 0,
		}

		if err := syscall.Sendto(e.sendFd, data, 0, addr); err != nil {
			utils.Debugf("[RAW-NIC%d] Sendto failed: %v", e.nicID, err)
			continue
		}

		e.packetOut.Add(1)
		n++
	}
	return n, nil
}

func (e *RawSocketEndpoint) Close() {
	syscall.Close(e.sendFd)
	syscall.Close(e.recvFd)
}
