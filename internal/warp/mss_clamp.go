package warp

import (
	"encoding/binary"

	"golang.zx2c4.com/wireguard/tun"
)

const (
	MinTCPMSS = 536
	MaxTCPMSS = 1460
)

// mssClampDevice rewrites only TCP SYN/SYN-ACK MSS options in both directions
// across the userspace tunnel. The netstack MTU remains unchanged, which keeps
// IPv6's minimum link MTU requirement intact while constraining TCP payloads.
type mssClampDevice struct {
	tun.Device
	maxMSS int
}

func newMSSClampDevice(device tun.Device, maxMSS int) tun.Device {
	return &mssClampDevice{Device: device, maxMSS: maxMSS}
}

func (d *mssClampDevice) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	n, err := d.Device.Read(bufs, sizes, offset)
	for i := 0; i < n; i++ {
		sizes[i] = clampTCPMSS(bufs[i][offset:offset+sizes[i]], d.maxMSS)
	}
	return n, err
}

func (d *mssClampDevice) Write(bufs [][]byte, offset int) (int, error) {
	for i := range bufs {
		clampTCPMSS(bufs[i][offset:], d.maxMSS)
	}
	return d.Device.Write(bufs, offset)
}

// clampTCPMSS returns the packet length and changes no bytes unless the packet
// is IPv4/IPv6 TCP with SYN set and an MSS option larger than maxMSS.
func clampTCPMSS(packet []byte, maxMSS int) int {
	if maxMSS == 0 || len(packet) < 20 {
		return len(packet)
	}
	var ipHeader, tcpOffset, tcpLength int
	switch packet[0] >> 4 {
	case 4:
		ipHeader = int(packet[0]&0x0f) * 4
		if ipHeader < 20 || len(packet) < ipHeader || packet[9] != 6 {
			return len(packet)
		}
		total := int(binary.BigEndian.Uint16(packet[2:4]))
		if total < ipHeader || total > len(packet) {
			return len(packet)
		}
		tcpOffset, tcpLength = ipHeader, total-ipHeader
	case 6:
		if len(packet) < 40 || packet[6] != 6 {
			return len(packet)
		}
		payload := int(binary.BigEndian.Uint16(packet[4:6]))
		if payload < 20 || 40+payload > len(packet) {
			return len(packet)
		}
		tcpOffset, tcpLength = 40, payload
	default:
		return len(packet)
	}
	if tcpLength < 20 || tcpOffset+tcpLength > len(packet) || packet[tcpOffset+13]&0x02 == 0 {
		return len(packet)
	}
	tcpHeader := int(packet[tcpOffset+12]>>4) * 4
	if tcpHeader < 20 || tcpHeader > tcpLength {
		return len(packet)
	}
	changed := false
	for pos := tcpOffset + 20; pos < tcpOffset+tcpHeader; {
		kind := packet[pos]
		if kind == 0 {
			break
		}
		if kind == 1 {
			pos++
			continue
		}
		if pos+2 > tcpOffset+tcpHeader {
			return len(packet)
		}
		length := int(packet[pos+1])
		if length < 2 || pos+length > tcpOffset+tcpHeader {
			return len(packet)
		}
		if kind == 2 && length == 4 {
			mss := int(binary.BigEndian.Uint16(packet[pos+2 : pos+4]))
			if mss > maxMSS {
				binary.BigEndian.PutUint16(packet[pos+2:pos+4], uint16(maxMSS))
				changed = true
			}
		}
		pos += length
	}
	if changed {
		binary.BigEndian.PutUint16(packet[tcpOffset+16:tcpOffset+18], 0)
		binary.BigEndian.PutUint16(packet[tcpOffset+16:tcpOffset+18], tcpChecksum(packet, tcpOffset, tcpLength))
	}
	return len(packet)
}

func tcpChecksum(packet []byte, offset, length int) uint16 {
	var sum uint32
	add := func(data []byte) {
		for len(data) >= 2 {
			sum += uint32(binary.BigEndian.Uint16(data[:2]))
			data = data[2:]
		}
		if len(data) == 1 {
			sum += uint32(data[0]) << 8
		}
	}
	if packet[0]>>4 == 4 {
		add(packet[12:20])
		var pseudo [8]byte
		pseudo[3] = 6
		binary.BigEndian.PutUint32(pseudo[4:], uint32(length))
		add(pseudo[:])
	} else {
		add(packet[8:40])
		var pseudo [8]byte
		binary.BigEndian.PutUint32(pseudo[:4], uint32(length))
		pseudo[7] = 6
		add(pseudo[:])
	}
	add(packet[offset : offset+length])
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
