package network

import (
	"fmt"
	"net"
	"strings"
)

func TCPChecksum(tcpData []byte, srcIP, dstIP [4]byte) uint16 {
	pseudoHeader := []byte{
		srcIP[0], srcIP[1], srcIP[2], srcIP[3],
		dstIP[0], dstIP[1], dstIP[2], dstIP[3],
		0, 6,
		0, 0,
	}

	tcpLen := len(tcpData)
	pseudoHeader[10] = byte(tcpLen >> 8)
	pseudoHeader[11] = byte(tcpLen & 0xff)

	all := make([]byte, 0, len(pseudoHeader)+tcpLen)
	all = append(all, pseudoHeader...)
	all = append(all, tcpData...)

	sum := uint32(0)
	for i := 0; i < len(all)-1; i += 2 {
		sum += uint32(all[i])<<8 | uint32(all[i+1])
	}
	if len(all)%2 == 1 {
		sum += uint32(all[len(all)-1]) << 8
	}

	for sum>>16 > 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}

	return uint16(^sum)
}

func IPChecksum(b []byte) uint16 {
	sum := uint32(0)
	for i := 0; i < len(b)-1; i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	sum = (sum >> 16) + (sum & 0xFFFF)
	sum += sum >> 16
	return uint16(^sum)
}

func ParsePacketInfo(data []byte) string {
	if len(data) < 20 {
		return fmt.Sprintf("short packet (%d bytes)", len(data))
	}
	ihl := int(data[0]&0x0F) * 4
	if ihl < 20 {
		return fmt.Sprintf("malformed IPv4 header (ihl=%d)", ihl)
	}
	srcIP := net.IP(data[12:16])
	dstIP := net.IP(data[16:20])
	protocol := data[9]
	ttl := data[8]
	totalLen := uint16(data[2])<<8 | uint16(data[3])

	if protocol == 6 {
		if len(data) < ihl+20 {
			return fmt.Sprintf("truncated TCP header (%d bytes, ihl=%d)", len(data), ihl)
		}
		tcp := data[ihl:]
		srcPort := uint16(tcp[0])<<8 | uint16(tcp[1])
		dstPort := uint16(tcp[2])<<8 | uint16(tcp[3])
		flags := tcp[13]
		seq := uint32(tcp[4])<<24 | uint32(tcp[5])<<16 | uint32(tcp[6])<<8 | uint32(tcp[7])
		ack := uint32(tcp[8])<<24 | uint32(tcp[9])<<16 | uint32(tcp[10])<<8 | uint32(tcp[11])
		window := uint16(tcp[14])<<8 | uint16(tcp[15])

		flagStr := ""
		if flags&0x02 != 0 {
			flagStr += "SYN "
		}
		if flags&0x10 != 0 {
			flagStr += "ACK "
		}
		if flags&0x01 != 0 {
			flagStr += "FIN "
		}
		if flags&0x04 != 0 {
			flagStr += "RST "
		}
		if flags&0x08 != 0 {
			flagStr += "PSH "
		}

		return fmt.Sprintf("TCP %s:%d -> %s:%d [%s] seq=%d ack=%d win=%d len=%d ttl=%d",
			srcIP, srcPort, dstIP, dstPort, strings.TrimSpace(flagStr), seq, ack, window, totalLen, ttl)
	}
	return fmt.Sprintf("IP proto=%d %s -> %s len=%d ttl=%d", protocol, srcIP, dstIP, totalLen, ttl)
}
