package warp

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/device"
)

// DiagnosticRegistration is an opaque, single-use WARP registration returned
// for diagnostic tools. Credentials remain private to this package.
type DiagnosticRegistration struct{ registration }

// EndpointInfo is a redacted endpoint description suitable for a report.
type EndpointInfo struct {
	Host string
	IP   string
	Port int
}

// RegisterDiagnostic performs one normal application registration.
func RegisterDiagnostic(ctx context.Context) (DiagnosticRegistration, error) {
	r := newRegistrar()
	registration, err := r.register(ctx)
	if err != nil {
		return DiagnosticRegistration{}, err
	}
	return DiagnosticRegistration{registration: registration}, nil
}

// DiagnosticEndpoints exposes only endpoint host/IP/port data.
func (r DiagnosticRegistration) DiagnosticEndpoints() []EndpointInfo {
	seen := map[string]bool{}
	var result []EndpointInfo
	for _, raw := range r.Endpoints {
		host, portText, err := net.SplitHostPort(raw)
		if err != nil {
			continue
		}
		port, _ := strconv.Atoi(portText)
		key := net.JoinHostPort(host, strconv.Itoa(port))
		if seen[key] {
			continue
		}
		seen[key] = true
		result = append(result, EndpointInfo{Host: host, IP: net.ParseIP(host).String(), Port: port})
	}
	return result
}

// DiagnosticTunnel is the real userspace WireGuard/netstack tunnel without the
// application's Cloudflare Trace probe. It is used to isolate handshake,
// transport and verification failures.
type DiagnosticTunnel struct {
	exit      *exit
	endpoints []string
	peerKey   string
}

// NewDiagnosticTunnel builds the same tunnel as the application, but lets the
// caller run individual checks instead of collapsing them into one probe.
func NewDiagnosticTunnel(ctx context.Context, registration DiagnosticRegistration, stack Stack, mtu, tcpMSS, endpointPort int, family string) (*DiagnosticTunnel, error) {
	reg := registration.registration
	reg.Endpoints = filterEndpointFamily(reg.Endpoints, family)
	if len(reg.Endpoints) == 0 {
		return nil, fmt.Errorf("no %s endpoint in registration", family)
	}
	reg.Endpoint = reg.Endpoints[0]
	e, err := newExitWithStackAndOptions(ctx, reg, stack, netip.Addr{}, mtu, endpointPort, tcpMSS, false)
	if err != nil {
		return nil, err
	}
	return &DiagnosticTunnel{exit: e, endpoints: reg.Endpoints, peerKey: reg.PeerPublicKey}, nil
}

// VerifyDiagnostic executes the same exit construction and Cloudflare Trace
// probe used by the application while reusing the supplied single account.
func VerifyDiagnostic(ctx context.Context, registration DiagnosticRegistration, stack Stack, mtu, tcpMSS, endpointPort int, family string) (time.Duration, string, error) {
	start := time.Now()
	var logMu sync.Mutex
	var logs []string
	logger := &device.Logger{
		Verbosef: func(format string, args ...any) {
			logMu.Lock()
			logs = append(logs, fmt.Sprintf(format, args...))
			logMu.Unlock()
		},
		Errorf: func(format string, args ...any) {
			logMu.Lock()
			logs = append(logs, fmt.Sprintf(format, args...))
			logMu.Unlock()
		},
	}
	reg := registration.registration
	reg.Endpoints = filterEndpointFamily(reg.Endpoints, family)
	if len(reg.Endpoints) == 0 {
		return time.Since(start), strings.Join(logs, " | "), fmt.Errorf("no %s endpoint in registration", family)
	}
	reg.Endpoint = reg.Endpoints[0]
	e, err := newExitWithStackAndLogger(ctx, reg, stack, netip.Addr{}, mtu, endpointPort, tcpMSS, true, logger)
	if err != nil {
		return time.Since(start), strings.Join(logs, " | "), err
	}
	e.close()
	return time.Since(start), strings.Join(logs, " | "), nil
}

func filterEndpointFamily(endpoints []string, family string) []string {
	want6 := strings.EqualFold(family, "ipv6") || strings.EqualFold(family, "v6")
	want4 := strings.EqualFold(family, "ipv4") || strings.EqualFold(family, "v4")
	if !want4 && !want6 {
		return append([]string(nil), endpoints...)
	}
	result := make([]string, 0, len(endpoints))
	for _, endpoint := range endpoints {
		host, _, err := net.SplitHostPort(endpoint)
		if err != nil {
			continue
		}
		ip := net.ParseIP(host)
		if (want4 && ip != nil && ip.To4() != nil) || (want6 && ip != nil && ip.To4() == nil) {
			result = append(result, endpoint)
		}
	}
	return result
}

// Close releases the userspace tunnel.
func (t *DiagnosticTunnel) Close() error {
	if t == nil || t.exit == nil {
		return nil
	}
	t.exit.close()
	return nil
}

// HandshakeStats is a redacted subset of WireGuard's UAPI get output.
type HandshakeStats struct {
	LastHandshakeSec int64
	TxBytes          int64
	RxBytes          int64
	Raw              string
}

// Handshake polls IpcGet until WireGuard reports a non-zero handshake.
func (t *DiagnosticTunnel) Handshake(ctx context.Context) (HandshakeStats, time.Duration, error) {
	start := time.Now()
	var last HandshakeStats
	for {
		raw, err := t.exit.device.IpcGet()
		if err != nil {
			return last, time.Since(start), err
		}
		last = parseHandshakeStats(raw)
		if last.LastHandshakeSec > 0 {
			last.Raw = raw
			return last, time.Since(start), nil
		}
		select {
		case <-ctx.Done():
			last.Raw = raw
			return last, time.Since(start), ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// Stats reads the current redacted WireGuard counters after probes complete.
func (t *DiagnosticTunnel) Stats() (HandshakeStats, error) {
	raw, err := t.exit.device.IpcGet()
	if err != nil {
		return HandshakeStats{}, err
	}
	stats := parseHandshakeStats(raw)
	stats.Raw = raw
	return stats, nil
}

func parseHandshakeStats(raw string) HandshakeStats {
	var result HandshakeStats
	for _, line := range strings.Split(raw, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		n, _ := strconv.ParseInt(value, 10, 64)
		switch key {
		case "last_handshake_time_sec":
			result.LastHandshakeSec = n
		case "tx_bytes":
			result.TxBytes = n
		case "rx_bytes":
			result.RxBytes = n
		}
	}
	return result
}

// Ping sends one ICMP echo through the tunnel.
func (t *DiagnosticTunnel) Ping(ctx context.Context, address string, size int) (time.Duration, error) {
	ip := net.ParseIP(address)
	if ip == nil {
		return 0, fmt.Errorf("invalid ping address %q", address)
	}
	conn, err := t.exit.network.DialPingAddr(netip.MustParseAddr(ip.String()), netip.MustParseAddr(ip.String()))
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(time.Until(deadline(ctx, 5*time.Second))))
	payload := make([]byte, size)
	start := time.Now()
	if _, err := conn.Write(payload); err != nil {
		return 0, err
	}
	read := make([]byte, size+64)
	if _, err := conn.Read(read); err != nil {
		return 0, err
	}
	return time.Since(start), nil
}

func deadline(ctx context.Context, fallback time.Duration) time.Time {
	if d, ok := ctx.Deadline(); ok {
		return d
	}
	return time.Now().Add(fallback)
}

// TCPConnect checks a TCP connection through the tunnel.
func (t *DiagnosticTunnel) TCPConnect(ctx context.Context, address string) (time.Duration, error) {
	start := time.Now()
	conn, err := t.exit.network.DialContext(ctx, "tcp", address)
	if err != nil {
		return time.Since(start), err
	}
	conn.Close()
	return time.Since(start), nil
}

// Trace performs the same Cloudflare Trace request used by the application.
func (t *DiagnosticTunnel) Trace(ctx context.Context, family string) (time.Duration, bool, error) {
	url := "https://1.1.1.1/cdn-cgi/trace"
	network := "tcp4"
	if strings.EqualFold(family, "ipv6") {
		url = "https://[2606:4700:4700::1111]/cdn-cgi/trace"
		network = "tcp6"
	}
	start := time.Now()
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, TLSHandshakeTimeout: 10 * time.Second, DialContext: func(ctx context.Context, _, address string) (net.Conn, error) {
		return t.exit.network.DialContext(ctx, network, address)
	}}
	defer transport.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return time.Since(start), false, err
	}
	resp, err := (&http.Client{Transport: transport}).Do(req)
	if err != nil {
		return time.Since(start), false, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	return time.Since(start), strings.Contains(string(data), "warp=on"), err
}

// Download fetches a bounded body through the tunnel.
func (t *DiagnosticTunnel) Download(ctx context.Context, bytes int) (time.Duration, int64, error) {
	start := time.Now()
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, DialContext: func(ctx context.Context, _, address string) (net.Conn, error) {
		return t.exit.network.DialContext(ctx, "tcp4", address)
	}}
	defer transport.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("https://speed.cloudflare.com/__down?bytes=%d", bytes), nil)
	if err != nil {
		return time.Since(start), 0, err
	}
	resp, err := (&http.Client{Transport: transport}).Do(req)
	if err != nil {
		return time.Since(start), 0, err
	}
	defer resp.Body.Close()
	n, err := io.Copy(io.Discard, io.LimitReader(resp.Body, int64(bytes)+1))
	return time.Since(start), n, err
}

// ParseHandshakeStats is exported for deterministic parser tests.
func ParseHandshakeStats(raw string) HandshakeStats { return parseHandshakeStats(raw) }
