package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestVersion(t *testing.T) {
	SetVersion("0.2.0", "abcdef1", "2026-10-18T21:00:00Z")

	b := bytes.NewBufferString("")
	rootCmd.SetOut(b)
	rootCmd.SetArgs([]string{"version"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if rootCmd.Version == "" {
		t.Error("expected rootCmd.Version to be non-empty")
	}
	if !strings.Contains(rootCmd.Version, "0.2.0") {
		t.Errorf("expected rootCmd.Version to contain 0.2.0, got %s", rootCmd.Version)
	}
}
