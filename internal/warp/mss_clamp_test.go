package warp

import (
	"encoding/binary"
	"testing"
)

func TestClampTCPMSSIPv4SYN(t *testing.T) {
	packet := testTCPPacket(false, true, 1460)
	before := append([]byte(nil), packet...)
	clampTCPMSS(packet, 1160)
	if got := binary.BigEndian.Uint16(packet[42:44]); got != 1160 {
		t.Fatalf("IPv4 MSS = %d, want 1160", got)
	}
	if !validTCPChecksum(packet) {
		t.Fatal("IPv4 TCP checksum invalid after clamp")
	}
	if before[0] != packet[0] || before[20] != packet[20] {
		t.Fatal("clamp changed non-MSS header bytes")
	}
}

func TestClampTCPMSSIPv6SYNACK(t *testing.T) {
	packet := testTCPPacket(true, true, 1460)
	packet[53] = 0x12 // SYN+ACK
	clampTCPMSS(packet, 1160)
	if got := binary.BigEndian.Uint16(packet[62:64]); got != 1160 {
		t.Fatalf("IPv6 MSS = %d, want 1160", got)
	}
	if !validTCPChecksum(packet) {
		t.Fatal("IPv6 TCP checksum invalid after clamp")
	}
}

func TestClampTCPMSSPreservesSmallerAndDisabled(t *testing.T) {
	for _, max := range []int{0, 1460} {
		packet := testTCPPacket(false, true, 1200)
		before := append([]byte(nil), packet...)
		clampTCPMSS(packet, max)
		if string(packet) != string(before) {
			t.Fatalf("MSS %d packet changed unexpectedly", max)
		}
	}
}

func TestClampTCPMSSLeavesNonTCPAndNonSYNUnchanged(t *testing.T) {
	udp := make([]byte, 40)
	udp[0] = 0x45
	udp[9] = 17
	before := append([]byte(nil), udp...)
	clampTCPMSS(udp, 1160)
	if string(udp) != string(before) {
		t.Fatal("non-TCP packet changed")
	}
	nonSyn := testTCPPacket(false, false, 1460)
	before = append([]byte(nil), nonSyn...)
	clampTCPMSS(nonSyn, 1160)
	if string(nonSyn) != string(before) {
		t.Fatal("non-SYN packet changed")
	}
}

func testTCPPacket(ipv6, syn bool, mss int) []byte {
	ipLen := 20
	if ipv6 {
		ipLen = 40
	}
	packet := make([]byte, ipLen+24)
	if ipv6 {
		packet[0] = 0x60
		binary.BigEndian.PutUint16(packet[4:6], 24)
		packet[6] = 6
		for i := 8; i < 40; i++ {
			packet[i] = byte(i)
		}
	} else {
		packet[0] = 0x45
		binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
		packet[8] = 64
		packet[9] = 6
		for i := 12; i < 20; i++ {
			packet[i] = byte(i)
		}
	}
	tcp := packet[ipLen:]
	binary.BigEndian.PutUint16(tcp[0:2], 1234)
	binary.BigEndian.PutUint16(tcp[2:4], 443)
	tcp[12] = 0x60
	if syn {
		tcp[13] = 2
	}
	tcp[20] = 2
	tcp[21] = 4
	binary.BigEndian.PutUint16(tcp[22:24], uint16(mss))
	binary.BigEndian.PutUint16(tcp[16:18], 0)
	binary.BigEndian.PutUint16(tcp[16:18], tcpChecksum(packet, ipLen, 24))
	return packet
}

func validTCPChecksum(packet []byte) bool {
	ipLen := 20
	if packet[0]>>4 == 6 {
		ipLen = 40
	}
	return tcpChecksum(packet, ipLen, len(packet)-ipLen) == 0
}
