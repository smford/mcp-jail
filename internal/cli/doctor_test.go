package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestDoctorCommand(t *testing.T) {
	b := bytes.NewBufferString("")
	rootCmd.SetOut(b)
	rootCmd.SetArgs([]string{"doctor", "--json"})

	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("doctor --json command failed: %v", err)
	}

	out := b.String()
	if !strings.Contains(out, "Flight Recorder") && !strings.Contains(out, "SQLite Database") {
		t.Errorf("expected SQLite Database check in doctor output, got %s", out)
	}
}
