package tunnel

import (
	"fmt"

	"golang.org/x/sys/windows"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"

	"github.com/leon03131/fork-openflux/utils"
)

const (
	IPPROTO_RAW = 255
)

// RawSocketEndpoint is the exit-node internet-facing link endpoint.
// Windows implementation; shared logic lives in rawsocket_common.go.
type RawSocketEndpoint struct {
	*rawSocketState
	sendFd windows.Handle
	recvFd windows.Handle
}

func NewRawSocketEndpoint(nicID tcpip.NICID, localIP [4]byte) (*RawSocketEndpoint, error) {
	sendFd, err := windows.Socket(windows.AF_INET, windows.SOCK_RAW, IPPROTO_RAW)
	if err != nil {
		return nil, fmt.Errorf("send socket failed: %v (need admin)", err)
	}

	if err := windows.SetsockoptInt(sendFd, windows.IPPROTO_IP, windows.IP_HDRINCL, 1); err != nil {
		windows.Close(sendFd)
		return nil, fmt.Errorf("IP_HDRINCL: %v", err)
	}

	recvFd, err := windows.Socket(windows.AF_INET, windows.SOCK_RAW, windows.IPPROTO_TCP)
	if err != nil {
		windows.Close(sendFd)
		return nil, fmt.Errorf("recv socket failed: %v (need admin)", err)
	}

	addr := &windows.SockaddrInet4{
		Addr: [4]byte{0, 0, 0, 0},
		Port: 0,
	}
	if err := windows.Bind(recvFd, addr); err != nil {
		windows.Close(sendFd)
		windows.Close(recvFd)
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
		n, _, err := windows.Recvfrom(e.recvFd, buf, 0)
		if err != nil {
			if err == windows.WSAEWOULDBLOCK {
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

		addr := &windows.SockaddrInet4{
			Addr: dst,
			Port: 0,
		}

		if err := windows.Sendto(e.sendFd, data, 0, addr); err != nil {
			utils.Debugf("[RAW-NIC%d] Sendto failed: %v", e.nicID, err)
			continue
		}

		e.packetOut.Add(1)
		n++
	}
	return n, nil
}

func (e *RawSocketEndpoint) Close() {
	windows.Close(e.sendFd)
	windows.Close(e.recvFd)
}
