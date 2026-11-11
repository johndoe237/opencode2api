package config

import (
	"os"
	"path/filepath"
	"testing"

	"opencode2api/internal/warp"
)

func TestWarpConfigNormalizeDefaultsMTU(t *testing.T) {
	cfg := WarpConfig{}
	if err := cfg.Normalize(); err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	if cfg.MTU != warp.DefaultMTU {
		t.Fatalf("default MTU = %d, want %d", cfg.MTU, warp.DefaultMTU)
	}
}

func TestWarpConfigNormalizeValidMTU(t *testing.T) {
	cfg := WarpConfig{MTU: 1200}
	if err := cfg.Normalize(); err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	if cfg.MTU != 1200 {
		t.Fatalf("MTU = %d, want 1200", cfg.MTU)
	}
}

func TestWarpConfigNormalizeDiagnosticOptions(t *testing.T) {
	cfg := WarpConfig{EndpointPort: 500, InitTimeoutSeconds: 45}
	if err := cfg.Normalize(); err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	if cfg.EndpointPort != 500 || cfg.InitTimeoutSeconds != 45 {
		t.Fatalf("diagnostic options changed: port=%d timeout=%d", cfg.EndpointPort, cfg.InitTimeoutSeconds)
	}
}

func TestWarpConfigNormalizeRejectsInvalidDiagnosticOptions(t *testing.T) {
	for _, cfg := range []WarpConfig{{EndpointPort: -1}, {EndpointPort: 65536}, {InitTimeoutSeconds: -1}, {InitTimeoutSeconds: 901}} {
		if err := cfg.Normalize(); err == nil {
			t.Fatalf("Normalize() accepted invalid diagnostic options: %+v", cfg)
		}
	}
}

func TestWarpConfigNormalizeTCPMSS(t *testing.T) {
	for _, mss := range []int{0, warp.MinTCPMSS, 1160, warp.MaxTCPMSS} {
		cfg := WarpConfig{TCPMSS: mss}
		if err := cfg.Normalize(); err != nil {
			t.Fatalf("Normalize() rejected tcp_mss %d: %v", mss, err)
		}
	}
	for _, mss := range []int{warp.MinTCPMSS - 1, warp.MaxTCPMSS + 1} {
		cfg := WarpConfig{TCPMSS: mss}
		if err := cfg.Normalize(); err == nil {
			t.Fatalf("Normalize() accepted tcp_mss %d", mss)
		}
	}
}

func TestWarpConfigNormalizeRejectsMTUOutsideBounds(t *testing.T) {
	for _, mtu := range []int{warp.MinMTU - 1, warp.MaxMTU + 1} {
		t.Run(string(rune(mtu)), func(t *testing.T) {
			cfg := WarpConfig{MTU: mtu}
			if err := cfg.Normalize(); err == nil {
				t.Fatalf("Normalize() accepted MTU %d", mtu)
			}
		})
	}
}

func TestLoadRejectsInvalidWarpMTU(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	data := []byte(`{
  "server_keys": ["local"],
  "anonymous": true,
  "warp": {"mtu": 999}
}`)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("Load() accepted an invalid warp.mtu")
	}
}

func TestWarpMTURoundTrip(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join("..", "..", "config.example.json")
	data, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("initial Load() error = %v", err)
	}
	cfg.Warp.MTU = 1200
	cfg.Warp.TCPMSS = 1160
	if err := SaveAtomic(path, cfg); err != nil {
		t.Fatalf("SaveAtomic() error = %v", err)
	}
	reloaded, err := Load(path)
	if err != nil {
		t.Fatalf("round-trip Load() error = %v", err)
	}
	if reloaded.Warp.MTU != 1200 {
		t.Fatalf("round-trip MTU = %d, want 1200", reloaded.Warp.MTU)
	}
	if reloaded.Warp.TCPMSS != 1160 {
		t.Fatalf("round-trip tcp_mss = %d, want 1160", reloaded.Warp.TCPMSS)
	}
}
