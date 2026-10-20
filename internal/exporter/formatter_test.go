package exporter

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/smford/mcp-jail/internal/recorder"
)

func TestFormatters(t *testing.T) {
	now := time.Date(2026, 10, 21, 0, 15, 0, 0, time.UTC)
	ev := &recorder.Event{
		ID:            101,
		SessionID:     "sess-xyz",
		Timestamp:     now,
		Direction:     recorder.DirectionHostToServer,
		RPCID:         "42",
		Method:        "tools/call",
		ToolName:      "execute_sql",
		Action:        recorder.ActionBlocked,
		RuleTriggered: "DROP DATABASE blocked",
		LatencyMs:     15,
		PayloadJSON:   `{"sql":"DROP DATABASE test"}`,
	}

	// 1. Test CEF format
	cefStr := FormatCEF(ev, "0.5.0")
	if !strings.HasPrefix(cefStr, "CEF:0|smford|mcp-jail|0.5.0|POLICY_VIOLATION|") {
		t.Errorf("unexpected CEF header: %s", cefStr)
	}
	if !strings.Contains(cefStr, "|7|") {
		t.Errorf("expected severity 7 for blocked action, got: %s", cefStr)
	}
	if !strings.Contains(cefStr, "act=blocked") || !strings.Contains(cefStr, "tool=execute_sql") || !strings.Contains(cefStr, "reason=DROP DATABASE blocked") {
		t.Errorf("CEF missing required extension attributes: %s", cefStr)
	}

	// 2. Test logfmt format
	logfmtStr := FormatLogfmt(ev)
	if !strings.Contains(logfmtStr, "level=warn") {
		t.Errorf("expected level=warn in logfmt, got: %s", logfmtStr)
	}
	if !strings.Contains(logfmtStr, "tool=execute_sql") {
		t.Errorf("expected tool=execute_sql in logfmt, got: %s", logfmtStr)
	}
	if !strings.Contains(logfmtStr, `rule="DROP DATABASE blocked"`) {
		t.Errorf("expected quoted rule in logfmt, got: %s", logfmtStr)
	}
	if !strings.Contains(logfmtStr, "latency_ms=15") {
		t.Errorf("expected latency_ms=15 in logfmt, got: %s", logfmtStr)
	}

	// 3. Test JSON format
	jsonData, err := FormatJSON(ev)
	if err != nil {
		t.Fatalf("FormatJSON failed: %v", err)
	}
	var unmarshaled recorder.Event
	if err := json.Unmarshal(jsonData, &unmarshaled); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}
	if unmarshaled.ToolName != "execute_sql" || unmarshaled.Action != recorder.ActionBlocked {
		t.Errorf("unmarshaled event mismatch: %+v", unmarshaled)
	}

	// 4. Test FormatEvent dispatcher
	for _, fmtName := range []string{"json", "cef", "logfmt"} {
		data, err := FormatEvent(fmtName, ev, "0.5.0")
		if err != nil {
			t.Errorf("FormatEvent(%s) returned error: %v", fmtName, err)
		}
		if len(data) == 0 {
			t.Errorf("FormatEvent(%s) returned empty data", fmtName)
		}
	}
}

func TestFormatCEF_Severities(t *testing.T) {
	evRedacted := &recorder.Event{
		Action:    recorder.ActionRedacted,
		ToolName:  "read_file",
		Timestamp: time.Now(),
	}
	cefRedacted := FormatCEF(evRedacted, "0.5.0")
	if !strings.Contains(cefRedacted, "|SECRET_REDACTED|") || !strings.Contains(cefRedacted, "|5|") {
		t.Errorf("expected severity 5 for redacted event, got: %s", cefRedacted)
	}

	evAllowed := &recorder.Event{
		Action:    recorder.ActionAllowed,
		ToolName:  "list_files",
		Timestamp: time.Now(),
	}
	cefAllowed := FormatCEF(evAllowed, "0.5.0")
	if !strings.Contains(cefAllowed, "|TOOL_INVOCATION|") || !strings.Contains(cefAllowed, "|1|") {
		t.Errorf("expected severity 1 for allowed event, got: %s", cefAllowed)
	}
}
