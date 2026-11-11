package warp

import "testing"

func TestParseHandshakeStats(t *testing.T) {
	stats := ParseHandshakeStats("private_key=redacted\nlast_handshake_time_sec=42\ntx_bytes=148\nrx_bytes=256\n")
	if stats.LastHandshakeSec != 42 || stats.TxBytes != 148 || stats.RxBytes != 256 {
		t.Fatalf("unexpected stats: %+v", stats)
	}
}

func TestForceEndpointPort(t *testing.T) {
	got := forceEndpointPort([]string{"162.159.192.1:2408", "[2606:4700:d0::a29f:c001]:2408", "engage.cloudflareclient.com:2408"}, 500)
	want := []string{"162.159.192.1:500", "[2606:4700:d0::a29f:c001]:500", "engage.cloudflareclient.com:500"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("endpoint %d = %q, want %q", i, got[i], want[i])
		}
	}
}
