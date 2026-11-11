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

var ports = []int{2408, 500, 1701, 4500, 854, 864, 880, 894, 903, 934, 939, 942, 955, 968, 987, 1002, 1010, 1070, 1180, 3138, 4198}

type result struct {
	family, port, mtu  string
	handshake          bool
	elapsed            time.Duration
	stats              warp.HandshakeStats
	icmpSmall, icmpBig string
	tcp, trace, down   string
	err                string
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
			fmt.Printf("config=loaded warp.stack=%s warp.mtu=%d endpoint_port=%d init_timeout_seconds=%d\n", cfg.Warp.Stack, cfg.Warp.MTU, cfg.Warp.EndpointPort, cfg.Warp.InitTimeoutSeconds)
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
	base := runMatrix(ctx, reg, cfg.Warp.Stack, []int{1200}, families, ports)
	hits := successful(base)
	if len(hits) > 0 {
		base = append(base, runMatrix(ctx, reg, cfg.Warp.Stack, []int{1280, 1100}, families, hits)...)
	}
	for _, r := range base {
		fmt.Printf("case family=%s port=%s mtu=%s handshake=%s time=%s last_handshake_time_sec=%d tx_bytes=%d rx_bytes=%d icmp56=%s icmp1172=%s tcp=%s trace=%s download=%s%s\n", r.family, r.port, r.mtu, yesNo(r.handshake), r.elapsed.Round(time.Millisecond), r.stats.LastHandshakeSec, r.stats.TxBytes, r.stats.RxBytes, r.icmpSmall, r.icmpBig, r.tcp, r.trace, r.down, formatError(r.err))
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

func runMatrix(ctx context.Context, reg warp.DiagnosticRegistration, stack string, mtus []int, families []string, ports []int) []result {
	type job struct {
		family    string
		port, mtu int
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
				out <- runCase(ctx, reg, stack, j.family, j.port, j.mtu)
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, mtu := range mtus {
			for _, family := range families {
				for _, port := range ports {
					select {
					case jobs <- job{family: family, port: port, mtu: mtu}:
					case <-ctx.Done():
						return
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
		return resultList[i].family+resultList[i].port+resultList[i].mtu < resultList[j].family+resultList[j].port+resultList[j].mtu
	})
	return resultList
}

func runCase(parent context.Context, reg warp.DiagnosticRegistration, stack, family string, port, mtu int) result {
	r := result{family: family, port: fmt.Sprint(port), mtu: fmt.Sprint(mtu), icmpSmall: "-", icmpBig: "-", tcp: "-", trace: "-", down: "-"}
	ctx, cancel := context.WithTimeout(parent, caseTimeout)
	defer cancel()
	start := time.Now()
	tunnel, err := warp.NewDiagnosticTunnel(ctx, reg, warp.Stack(stackForFamily(stack, family)), mtu, port, family)
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
	r.icmpSmall = checkPing(ctx, tunnel, family, 56)
	r.icmpBig = checkPing(ctx, tunnel, family, 1172)
	r.tcp = checkTCP(ctx, tunnel, family)
	r.trace = checkTrace(ctx, tunnel, family)
	r.down = checkDownload(ctx, tunnel)
	return r
}

func stackForFamily(stack, family string) string {
	if stack == "dual" {
		return family
	}
	return stack
}

func checkPing(ctx context.Context, tunnel *warp.DiagnosticTunnel, family string, size int) string {
	address := "1.1.1.1"
	if family == "ipv6" {
		address = "2606:4700:4700::1111"
	}
	d, err := tunnel.Ping(ctx, address, size)
	if err != nil {
		return "N"
	}
	return d.Round(time.Millisecond).String()
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

func successful(results []result) []int {
	seen := map[int]bool{}
	var values []int
	for _, r := range results {
		if r.handshake {
			var p int
			fmt.Sscanf(r.port, "%d", &p)
			if !seen[p] {
				seen[p] = true
				values = append(values, p)
			}
		}
	}
	return values
}

func printRawUDP(reg warp.DiagnosticRegistration) {
	for _, ep := range reg.DiagnosticEndpoints() {
		if ep.IP == "<nil>" || ep.IP == "" {
			continue
		}
		addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(ep.IP, fmt.Sprint(ep.Port)))
		if err != nil {
			continue
		}
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
	duration, logs, err := warp.VerifyDiagnostic(caseCtx, reg, warp.Stack(family), cfg.Warp.MTU, cfg.Warp.EndpointPort, family)
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
	fmt.Printf("RECOMMENDED CONFIG: {\"warp\":{\"enabled\":true,\"stack\":\"%s\",\"mtu\":%s,\"endpoint_port\":%s,\"init_timeout_seconds\":%d}}\n", best.family, best.mtu, best.port, cfg.Warp.InitTimeoutSeconds)
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
	for _, r := range handshakes {
		if r.icmpBig == "N" || r.tcp == "N" || r.trace == "N" {
			return fmt.Sprintf("handshake observed on family=%s port=%s mtu=%s but downstream checks fail; investigate PMTU or post-handshake filtering", r.family, r.port, r.mtu), &r
		}
	}
	return fmt.Sprintf("handshake and downstream checks observed on family=%s port=%s mtu=%s", best.family, best.port, best.mtu), &best
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
