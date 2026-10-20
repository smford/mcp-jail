package cli

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/smford/mcp-jail/internal/recorder"
)

func TestLogsCmd_Formats(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "flight-recorder.db")

	rec, err := recorder.NewRecorder(dbPath)
	if err != nil {
		t.Fatalf("failed to create recorder: %v", err)
	}

	sessionID := "sess-logs-test"
	sess := &recorder.Session{
		ID:         sessionID,
		StartedAt:  time.Now(),
		Command:    "test-cmd",
		Cwd:        tempDir,
		TotalCalls: 1,
	}
	if err := rec.StartSession(sess); err != nil {
		t.Fatalf("failed to start session: %v", err)
	}

	rec.RecordEvent(&recorder.Event{
		SessionID:     sessionID,
		Timestamp:     time.Now(),
		Direction:     recorder.DirectionHostToServer,
		RPCID:         "10",
		Method:        "tools/call",
		ToolName:      "read_file",
		Action:        recorder.ActionBlocked,
		RuleTriggered: "filesystem_boundary",
		PayloadJSON:   `{"path":"/etc/passwd"}`,
	})
	_ = rec.Close()

	formats := []struct {
		name     string
		format   string
		expected []string
	}{
		{
			name:     "table",
			format:   "table",
			expected: []string{"TIMESTAMP", "read_file", "BLOCKED", "Rule: filesystem_boundary"},
		},
		{
			name:     "json",
			format:   "json",
			expected: []string{`"tool_name":"read_file"`, `"action":"blocked"`, `"rule_triggered":"filesystem_boundary"`},
		},
		{
			name:     "cef",
			format:   "cef",
			expected: []string{"CEF:0|smford|mcp-jail|", "POLICY_VIOLATION", "tool=read_file", "act=blocked"},
		},
		{
			name:     "logfmt",
			format:   "logfmt",
			expected: []string{"level=warn", "tool=read_file", "action=blocked", "rule=filesystem_boundary"},
		},
	}

	for _, tc := range formats {
		t.Run(tc.name, func(t *testing.T) {
			buf := new(bytes.Buffer)
			rootCmd.SetOut(buf)
			rootCmd.SetArgs([]string{"logs", "--db", dbPath, "--format", tc.format})
			if err := rootCmd.Execute(); err != nil {
				t.Fatalf("logs --format %s failed: %v", tc.format, err)
			}
			out := buf.String()
			for _, exp := range tc.expected {
				if !strings.Contains(out, exp) {
					t.Errorf("format %s expected %q in output, got: %s", tc.format, exp, out)
				}
			}
		})
	}
}
