package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg == nil {
		t.Fatal("expected non-nil default config")
	}
	if cfg.Limits.MaxToolCallsPerMinute != 60 {
		t.Errorf("expected 60 max calls/min, got %d", cfg.Limits.MaxToolCallsPerMinute)
	}
	if len(cfg.Filesystem.DeniedPaths) == 0 {
		t.Errorf("expected denied paths to be populated")
	}
}

func TestLoadConfigCustom(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, ".mcp-jail.yaml")
	yamlContent := `
version: "1"
limits:
  max_tool_calls_per_minute: 120
tools:
  denied:
    - "^custom_tool$"
`
	if err := os.WriteFile(configPath, []byte(yamlContent), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	if cfg.Limits.MaxToolCallsPerMinute != 120 {
		t.Errorf("expected 120, got %d", cfg.Limits.MaxToolCallsPerMinute)
	}
	if len(cfg.Tools.Denied) != 1 || cfg.Tools.Denied[0] != "^custom_tool$" {
		t.Errorf("unexpected denied tools: %v", cfg.Tools.Denied)
	}
}
