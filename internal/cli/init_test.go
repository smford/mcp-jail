package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInitCmd(t *testing.T) {
	tempDir := t.TempDir()
	origWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get wd: %v", err)
	}
	defer func() {
		_ = os.Chdir(origWd)
	}()

	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("failed to chdir to tempDir: %v", err)
	}

	// 1. Test --list-presets
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetArgs([]string{"init", "--list-presets"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("init --list-presets failed: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "Available security presets:") {
		t.Errorf("expected header in list-presets, got: %s", out)
	}
	if !strings.Contains(out, "coding") || !strings.Contains(out, "database") || !strings.Contains(out, "github") {
		t.Errorf("expected preset names in list-presets, got: %s", out)
	}

	// 2. Test init with preset coding
	initListPresets = false
	buf.Reset()
	rootCmd.SetArgs([]string{"init", "--preset", "coding"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("init --preset coding failed: %v", err)
	}

	target := filepath.Join(tempDir, ".mcp-jail.yaml")
	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("expected .mcp-jail.yaml to be created: %v", err)
	}
	if !strings.Contains(string(data), "Preset: coding") {
		t.Errorf("expected coding preset content, got: %s", string(data))
	}

	// 3. Test overwrite fails without --force
	buf.Reset()
	rootCmd.SetArgs([]string{"init", "--preset", "database"})
	if err := rootCmd.Execute(); err == nil {
		t.Errorf("expected error when file exists without --force, got nil")
	}

	// 4. Test overwrite succeeds with --force
	buf.Reset()
	rootCmd.SetArgs([]string{"init", "--preset", "database", "--force"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("init --force failed: %v", err)
	}
	data, err = os.ReadFile(target)
	if err != nil {
		t.Fatalf("failed to read updated .mcp-jail.yaml: %v", err)
	}
	if !strings.Contains(string(data), "Preset: database") {
		t.Errorf("expected database preset content after force overwrite, got: %s", string(data))
	}
}
