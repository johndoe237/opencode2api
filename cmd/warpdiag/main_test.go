package main

import "testing"

func TestDecideVerdictNoHandshake(t *testing.T) {
	message, best := decideVerdict([]result{{family: "ipv4", port: "2408", mtu: "1200"}})
	if best != nil || message == "" {
		t.Fatalf("unexpected no-handshake decision: message=%q best=%+v", message, best)
	}
}

func TestDecideVerdictDownstreamFailure(t *testing.T) {
	message, best := decideVerdict([]result{{family: "ipv4", port: "500", mtu: "1200", handshake: true, icmpBig: "N", tcp: "10ms", trace: "N", down: "N/0"}})
	if best == nil || message == "" {
		t.Fatalf("unexpected downstream decision: message=%q best=%+v", message, best)
	}
}

func TestDecideVerdictSuccess(t *testing.T) {
	message, best := decideVerdict([]result{{family: "ipv6", port: "2408", mtu: "1200", handshake: true, icmpBig: "8ms", tcp: "20ms", trace: "30ms/Y", down: "100ms/300000"}})
	if best == nil || best.port != "2408" || message == "" {
		t.Fatalf("unexpected success decision: message=%q best=%+v", message, best)
	}
}
