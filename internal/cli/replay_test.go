package cli

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/smford/mcp-jail/internal/recorder"
)

func TestReplay_List(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "flight-recorder.db")

	rec, err := recorder.NewRecorder(dbPath)
	if err != nil {
		t.Fatalf("failed to create recorder: %v", err)
	}

	sess := &recorder.Session{
		ID:         "sess-test-123",
		StartedAt:  time.Now(),
		Command:    "npx -y @modelcontextprotocol/server-postgres",
		Cwd:        tempDir,
		TotalCalls: 5,
	}
	if err := rec.StartSession(sess); err != nil {
		t.Fatalf("failed to start session: %v", err)
	}
	_ = rec.Close()

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetArgs([]string{"replay", "--db", dbPath, "--list"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("replay --list failed: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "sess-test-123") {
		t.Errorf("expected sess-test-123 in replay list, got: %s", out)
	}
	if !strings.Contains(out, "@modelcontextprotocol") {
		t.Errorf("expected @modelcontextprotocol in replay list, got: %s", out)
	}
}

func TestReplay_MockServer(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "flight-recorder.db")

	rec, err := recorder.NewRecorder(dbPath)
	if err != nil {
		t.Fatalf("failed to create recorder: %v", err)
	}
	defer rec.Close()

	sessionID := "sess-replay-456"
	sess := &recorder.Session{
		ID:         sessionID,
		StartedAt:  time.Now(),
		Command:    "test-server",
		Cwd:        tempDir,
		TotalCalls: 3,
	}
	if err := rec.StartSession(sess); err != nil {
		t.Fatalf("failed to start session: %v", err)
	}

	// Record events
	rec.RecordEvent(&recorder.Event{
		SessionID:   sessionID,
		Timestamp:   time.Now(),
		Direction:   recorder.DirectionServerToHost,
		Method:      "initialize",
		PayloadJSON: `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05","capabilities":{"tools":{}}}}`,
	})
	rec.RecordEvent(&recorder.Event{
		SessionID:   sessionID,
		Timestamp:   time.Now(),
		Direction:   recorder.DirectionServerToHost,
		Method:      "tools/list",
		PayloadJSON: `{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"query_db","description":"Run SQL"}]}}`,
	})
	rec.RecordEvent(&recorder.Event{
		SessionID:   sessionID,
		Timestamp:   time.Now(),
		Direction:   recorder.DirectionServerToHost,
		Method:      "tools/call",
		ToolName:    "query_db",
		PayloadJSON: `{"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":"[{\"id\":1,\"name\":\"Alice\"}]"}]}}`,
	})

	// Wait for recorder worker to persist
	time.Sleep(100 * time.Millisecond)

	// Simulate incoming client requests
	inputRequests := strings.Join([]string{
		`{"jsonrpc":"2.0","id":"client-init","method":"initialize","params":{}}`,
		`{"jsonrpc":"2.0","id":42,"method":"tools/list","params":{}}`,
		`{"jsonrpc":"2.0","id":"call-99","method":"tools/call","params":{"name":"query_db","arguments":{"sql":"SELECT * FROM users"}}}`,
		`{"jsonrpc":"2.0","id":100,"method":"tools/call","params":{"name":"unknown_tool","arguments":{}}}`,
	}, "\n") + "\n"

	in := strings.NewReader(inputRequests)
	out := new(bytes.Buffer)
	errOut := new(bytes.Buffer)

	if err := RunReplay(in, out, errOut, rec, sessionID, false); err != nil {
		t.Fatalf("RunReplay failed: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 4 {
		t.Fatalf("expected 4 responses, got %d:\n%s", len(lines), out.String())
	}

	// 1. Verify initialize response
	var initResp struct {
		ID     string                 `json:"id"`
		Result map[string]interface{} `json:"result"`
	}
	if err := json.Unmarshal([]byte(lines[0]), &initResp); err != nil {
		t.Fatalf("failed to parse init resp: %v", err)
	}
	if initResp.ID != "client-init" || initResp.Result["protocolVersion"] != "2024-11-05" {
		t.Errorf("unexpected init resp: %s", lines[0])
	}

	// 2. Verify tools/list response
	var listResp struct {
		ID     int                    `json:"id"`
		Result map[string]interface{} `json:"result"`
	}
	if err := json.Unmarshal([]byte(lines[1]), &listResp); err != nil {
		t.Fatalf("failed to parse list resp: %v", err)
	}
	if listResp.ID != 42 || listResp.Result["tools"] == nil {
		t.Errorf("unexpected list resp: %s", lines[1])
	}

	// 3. Verify query_db response
	var callResp struct {
		ID     string                 `json:"id"`
		Result map[string]interface{} `json:"result"`
	}
	if err := json.Unmarshal([]byte(lines[2]), &callResp); err != nil {
		t.Fatalf("failed to parse call resp: %v", err)
	}
	if callResp.ID != "call-99" {
		t.Errorf("expected ID call-99, got: %s", lines[2])
	}

	// 4. Verify unknown_tool error response
	var errResp struct {
		ID    int                    `json:"id"`
		Error map[string]interface{} `json:"error"`
	}
	if err := json.Unmarshal([]byte(lines[3]), &errResp); err != nil {
		t.Fatalf("failed to parse err resp: %v", err)
	}
	if errResp.ID != 100 || errResp.Error == nil {
		t.Errorf("expected error response for unknown tool: %s", lines[3])
	}
}
