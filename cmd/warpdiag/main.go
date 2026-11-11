// Command warpdiag diagnoses the real userspace WARP path without TUN, root or NET_ADMIN.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"opencode2api/internal/config"
	"opencode2api/internal/warp"
)

var version = "dev"

const caseTimeout = 8 * time.Second
const diagnosticEndpointPort = 2408

type result struct {
	internal, external, mtu, tcpMSS string
	handshake                       bool
	elapsed                         time.Duration
	stats                           warp.HandshakeStats
	tcp, trace, down                string
	err                             string
}

func main() {
	configPath := flag.String("config", "", "path to config.json (optional)")
	total := flag.Duration("timeout", 300*time.Second, "total diagnostic timeout")
	flag.Parse()
	if *total <= 0 {
		*total = 300 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), *total)
	defer cancel()

	fmt.Println("===== WARPDIAG REPORT BEGIN =====")
	fmt.Printf("version=%s go=%s/%s local=%s\n", version, runtime.GOOS, runtime.GOARCH, time.Now().Format(time.RFC3339))
	printEnvironment(ctx)

	cfg := config.Config{Warp: config.WarpConfig{Stack: string(warp.DefaultStack), MTU: warp.DefaultMTU}}
	if *configPath != "" {
		loaded, err := config.Load(*configPath)
		if err != nil {
			fmt.Printf("config=ERROR %s\n", safeError(err))
		} else {
			cfg = loaded
			fmt.Printf("config=loaded warp.stack=%s warp.mtu=%d tcp_mss=%d endpoint_port=%d init_timeout_seconds=%d\n", cfg.Warp.Stack, cfg.Warp.MTU, cfg.Warp.TCPMSS, cfg.Warp.EndpointPort, cfg.Warp.InitTimeoutSeconds)
		}
	} else {
		_ = cfg.Warp.Normalize()
		fmt.Println("config=default diagnostic config (no credentials loaded)")
	}
	fmt.Printf("app_init_timeout_historical=%s probe_timeout=5s case_timeout=%s\n", warp.HistoricalInitTimeout, caseTimeout)

	regStart := time.Now()
	reg, err := warp.RegisterDiagnostic(ctx)
	if err != nil {
		fmt.Printf("registration=ERROR duration=%s error=%s\n", time.Since(regStart).Round(time.Millisecond), safeError(err))
		fmt.Println("VERDICT: registration failure or Cloudflare rate limit; no tunnel matrix was possible.")
		fmt.Println("===== WARPDIAG REPORT END =====")
		return
	}
	fmt.Printf("registration=OK duration=%s endpoints=%s\n", time.Since(regStart).Round(time.Millisecond), endpointText(reg.DiagnosticEndpoints()))

	families := []string{"ipv4", "ipv6"}
	base := runMatrix(ctx, reg, []string{"ipv4", "ipv6"}, families, []int{1280, 1200}, []int{0, 1160})
	for _, r := range base {
		fmt.Printf("case internal=%s external=%s mtu=%s tcp_mss=%s handshake=%s time=%s last_handshake_time_sec=%d tx_bytes=%d rx_bytes=%d tcp=%s trace=%s download=%s%s\n", r.internal, r.external, r.mtu, r.tcpMSS, yesNo(r.handshake), r.elapsed.Round(time.Millisecond), r.stats.LastHandshakeSec, r.stats.TxBytes, r.stats.RxBytes, r.tcp, r.trace, r.down, formatError(r.err))
	}
	if *configPath != "" {
		printApplicationFlow(ctx, reg, cfg)
	}
	if len(base) == 0 {
		fmt.Println("matrix=NO_CASES (registration returned no usable endpoint family)")
	}
	printRawUDP(reg)
	printVerdict(base, cfg)
	fmt.Println("===== WARPDIAG REPORT END =====")
}

func printEnvironment(ctx context.Context) {
	data, _ := os.ReadFile("/proc/net/dev")
	fmt.Printf("interfaces=%s\n", compactInterfaces(string(data)))
	request, _ := http.NewRequestWithContext(ctx, http.MethodHead, "https://www.cloudflare.com/", nil)
	start := time.Now()
	resp, err := http.DefaultClient.Do(request)
	if err != nil {
		fmt.Printf("cloudflare_date=ERROR %s\n", safeError(err))
		return
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	fmt.Printf("cloudflare_date=%q local_at_response=%s rtt=%s\n", resp.Header.Get("Date"), time.Now().Format(time.RFC3339), time.Since(start).Round(time.Millisecond))
}

func compactInterfaces(raw string) string {
	var values []string
	for _, line := range strings.Split(raw, "\n") {
		if !strings.Contains(line, ":") || strings.HasPrefix(strings.TrimSpace(line), "Inter") {
			continue
		}
		name := strings.TrimSpace(strings.SplitN(line, ":", 2)[0])
		mtu, _ := os.ReadFile("/sys/class/net/" + name + "/mtu")
		values = append(values, fmt.Sprintf("%s=%s", name, strings.TrimSpace(string(mtu))))
	}
	sort.Strings(values)
	return strings.Join(values, ",")
}

func runMatrix(ctx context.Context, reg warp.DiagnosticRegistration, internalFamilies, externalFamilies []string, mtus, msses []int) []result {
	type job struct {
		internal, external string
		mtu, tcpMSS        int
	}
	jobs := make(chan job)
	out := make(chan result)
	var wg sync.WaitGroup
	workers := 8
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				out <- runCase(ctx, reg, j.internal, j.external, j.mtu, j.tcpMSS)
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, mtu := range mtus {
			for _, internal := range internalFamilies {
				for _, external := range externalFamilies {
					for _, tcpMSS := range msses {
						select {
						case jobs <- job{internal: internal, external: external, mtu: mtu, tcpMSS: tcpMSS}:
						case <-ctx.Done():
							return
						}
					}
				}
			}
		}
	}()
	go func() { wg.Wait(); close(out) }()
	var resultList []result
	for r := range out {
		resultList = append(resultList, r)
	}
	sort.Slice(resultList, func(i, j int) bool {
		return resultList[i].internal+resultList[i].external+resultList[i].mtu+resultList[i].tcpMSS < resultList[j].internal+resultList[j].external+resultList[j].mtu+resultList[j].tcpMSS
	})
	return resultList
}

func runCase(parent context.Context, reg warp.DiagnosticRegistration, internal, external string, mtu, tcpMSS int) result {
	r := result{internal: internal, external: external, mtu: fmt.Sprint(mtu), tcpMSS: fmt.Sprint(tcpMSS), tcp: "-", trace: "-", down: "-"}
	ctx, cancel := context.WithTimeout(parent, caseTimeout)
	defer cancel()
	start := time.Now()
	tunnel, err := warp.NewDiagnosticTunnel(ctx, reg, warp.Stack(internal), mtu, tcpMSS, diagnosticEndpointPort, external)
	if err != nil {
		r.elapsed = time.Since(start)
		r.err = safeError(err)
		return r
	}
	defer tunnel.Close()
	stats, elapsed, err := tunnel.Handshake(ctx)
	r.elapsed, r.stats = elapsed, stats
	if err != nil {
		r.err = safeError(err)
		return r
	}
	r.handshake = true
	r.tcp = checkTCP(ctx, tunnel, internal)
	r.trace = checkTrace(ctx, tunnel, internal)
	r.down = checkDownload(ctx, tunnel)
	if stats, statsErr := tunnel.Stats(); statsErr == nil {
		r.stats = stats
	}
	return r
}

func checkTCP(ctx context.Context, tunnel *warp.DiagnosticTunnel, family string) string {
	address := "1.1.1.1:443"
	if family == "ipv6" {
		address = "[2606:4700:4700::1111]:443"
	}
	d, err := tunnel.TCPConnect(ctx, address)
	if err != nil {
		return "N"
	}
	return d.Round(time.Millisecond).String()
}

func checkTrace(ctx context.Context, tunnel *warp.DiagnosticTunnel, family string) string {
	d, on, err := tunnel.Trace(ctx, family)
	if err != nil {
		return "N"
	}
	return fmt.Sprintf("%s/%s", d.Round(time.Millisecond), yesNo(on))
}

func checkDownload(ctx context.Context, tunnel *warp.DiagnosticTunnel) string {
	d, n, err := tunnel.Download(ctx, 300000)
	if err != nil {
		return fmt.Sprintf("N/%d", n)
	}
	return fmt.Sprintf("%s/%d", d.Round(time.Millisecond), n)
}

func printRawUDP(reg warp.DiagnosticRegistration) {
	seenFamily := map[string]bool{}
	for _, ep := range reg.DiagnosticEndpoints() {
		if ep.IP == "<nil>" || ep.IP == "" {
			continue
		}
		addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(ep.IP, fmt.Sprint(ep.Port)))
		if err != nil {
			continue
		}
		family := "ipv6"
		if net.ParseIP(ep.IP).To4() != nil {
			family = "ipv4"
		}
		if ep.Port != diagnosticEndpointPort || seenFamily[family] {
			continue
		}
		seenFamily[family] = true
		conn, err := net.DialUDP("udp", nil, addr)
		if err != nil {
			continue
		}
		var parts []string
		for _, size := range []int{148, 512, 1200, 1280} {
			n, writeErr := conn.Write(make([]byte, size))
			parts = append(parts, fmt.Sprintf("%d:%d/%s", size, n, errorCode(writeErr)))
		}
		conn.Close()
		fmt.Printf("raw_udp endpoint=%s sizes=%s note=IP_RECVERR not available via portable net.UDPConn\n", net.JoinHostPort(ep.IP, fmt.Sprint(ep.Port)), strings.Join(parts, ","))
	}
}

func printApplicationFlow(ctx context.Context, reg warp.DiagnosticRegistration, cfg config.Config) {
	family := cfg.Warp.Stack
	if family == "dual" {
		family = "ipv6"
	}
	caseCtx, cancel := context.WithTimeout(ctx, caseTimeout)
	defer cancel()
	duration, logs, err := warp.VerifyDiagnostic(caseCtx, reg, warp.Stack(family), cfg.Warp.MTU, cfg.Warp.TCPMSS, cfg.Warp.EndpointPort, family)
	if err != nil {
		fmt.Printf("application_flow=ERROR phase=construction_or_verification duration=%s error=%s wireguard_verbose=%s\n", duration.Round(time.Millisecond), safeError(err), safeText(logs))
		return
	}
	fmt.Printf("application_flow=OK phase=verification duration=%s wireguard_verbose=%s note=exact_exit_probe_reusing_single_registration\n", duration.Round(time.Millisecond), safeText(logs))
}

func printVerdict(results []result, cfg config.Config) {
	decision, best := decideVerdict(results)
	fmt.Printf("VERDICT: %s\n", decision)
	if best == nil {
		return
	}
	fmt.Printf("RECOMMENDED CONFIG: {\"warp\":{\"enabled\":true,\"stack\":\"%s\",\"mtu\":%s,\"tcp_mss\":%s,\"init_timeout_seconds\":%d}}\n", best.internal, best.mtu, best.tcpMSS, cfg.Warp.InitTimeoutSeconds)
}

func decideVerdict(results []result) (string, *result) {
	var handshakes []result
	for _, r := range results {
		if r.handshake {
			handshakes = append(handshakes, r)
		}
	}
	if len(handshakes) == 0 {
		return "no handshake observed in the tested endpoint/family/MTU matrix; distinguish silent UDP filtering from an endpoint-specific failure with raw_udp results", nil
	}
	best := handshakes[0]
	for _, r := range handshakes[1:] {
		if resultScore(r) > resultScore(best) {
			best = r
		}
	}
	return fmt.Sprintf("best internal=%s external=%s mtu=%s tcp_mss=%s score=%d; compared %d handshake cases", best.internal, best.external, best.mtu, best.tcpMSS, resultScore(best), len(handshakes)), &best
}

func resultScore(r result) int {
	score := 1
	if r.tcp != "N" && r.tcp != "-" {
		score += 2
	}
	if strings.HasSuffix(r.trace, "/Y") {
		score += 4
	}
	if !strings.HasPrefix(r.down, "N/") && r.down != "-" {
		score += 4
	}
	if r.tcpMSS == "1160" {
		score++
	}
	return score
}

func endpointText(endpoints []warp.EndpointInfo) string {
	var values []string
	for _, e := range endpoints {
		values = append(values, fmt.Sprintf("%s:%d", e.Host, e.Port))
	}
	return strings.Join(values, ",")
}
func safeError(err error) string {
	return strings.NewReplacer("\n", " ", "\r", " ").Replace(err.Error())
}
func safeText(value string) string {
	return strings.NewReplacer("\n", " ", "\r", " ", "=", ":").Replace(value)
}
func formatError(err string) string {
	if err == "" {
		return ""
	}
	return " error=" + err
}
func yesNo(v bool) string {
	if v {
		return "Y"
	}
	return "N"
}
func errorCode(err error) string {
	if err == nil {
		return "OK"
	}
	return strings.ReplaceAll(err.Error(), " ", "_")
}
