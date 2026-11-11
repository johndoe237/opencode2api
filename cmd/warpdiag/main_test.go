package main

import "testing"

func TestDecideVerdictNoHandshake(t *testing.T) {
	message, best := decideVerdict([]result{{internal: "ipv4", external: "ipv6", mtu: "1200", tcpMSS: "0"}})
	if best != nil || message == "" {
		t.Fatalf("unexpected no-handshake decision: message=%q best=%+v", message, best)
	}
}

func TestDecideVerdictDownstreamFailure(t *testing.T) {
	message, best := decideVerdict([]result{{internal: "ipv4", external: "ipv6", mtu: "1200", tcpMSS: "0", handshake: true, tcp: "10ms", trace: "N", down: "N/0"}})
	if best == nil || message == "" {
		t.Fatalf("unexpected downstream decision: message=%q best=%+v", message, best)
	}
}

func TestDecideVerdictSuccess(t *testing.T) {
	message, best := decideVerdict([]result{{internal: "ipv6", external: "ipv4", mtu: "1280", tcpMSS: "1160", handshake: true, tcp: "20ms", trace: "30ms/Y", down: "100ms/300000"}})
	if best == nil || best.internal != "ipv6" || message == "" {
		t.Fatalf("unexpected success decision: message=%q best=%+v", message, best)
	}
}
