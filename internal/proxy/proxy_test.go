package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/smford/mcp-jail/internal/config"
	"github.com/smford/mcp-jail/internal/recorder"
)

func TestEndToEndProxyWithMockMCPServer(t *testing.T) {
	tempDir := t.TempDir()

	// 1. Compile the mock MCP server
	mockBin := filepath.Join(tempDir, "mock_mcp_server")
	buildCmd := exec.Command("go", "build", "-o", mockBin, "../../testdata/mock_mcp_server.go")
	buildOut, err := buildCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to build mock mcp server: %v, output: %s", err, string(buildOut))
	}

	workspaceDir := filepath.Join(tempDir, "workspace")
	if err := os.MkdirAll(workspaceDir, 0755); err != nil {
		t.Fatalf("failed to create workspace dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(workspaceDir, "safe.txt"), []byte("dummy safe content"), 0644); err != nil {
		t.Fatalf("failed to create safe.txt: %v", err)
	}

	dbPath := filepath.Join(tempDir, "flight-recorder.db")

	cfg := config.DefaultConfig()
	cfg.Filesystem.AllowedRoots = []string{workspaceDir}
	// Set limit to 4 total calls to test circuit breaker on 5th
	cfg.Limits.MaxTotalCallsPerSession = 4

	hostInR, hostInW := io.Pipe()
	hostOutR, hostOutW := io.Pipe()
	var hostErrBuf bytes.Buffer

	opts := Options{
		Config:    cfg,
		SessionID: "e2e-session-123",
		DBPath:    dbPath,
		Command:   mockBin,
		Cwd:       workspaceDir,
		HostIn:    hostInR,
		HostOut:   hostOutW,
		HostErr:   &hostErrBuf,
	}

	p, err := NewProxy(opts)
	if err != nil {
		t.Fatalf("failed to create proxy: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	proxyDone := make(chan error, 1)
	go func() {
		_, runErr := p.Run(ctx)
		proxyDone <- runErr
	}()

	scanner := bufio.NewScanner(hostOutR)
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, MaxLineSize)

	sendAndReceive := func(reqJSON string) map[string]interface{} {
		t.Helper()
		_, err := fmt.Fprintln(hostInW, reqJSON)
		if err != nil {
			t.Fatalf("failed to send req: %v", err)
		}

		if !scanner.Scan() {
			t.Fatalf("failed to read response line from proxy: %v", scanner.Err())
		}
		respLine := scanner.Bytes()

		var parsed map[string]interface{}
		if err := json.Unmarshal(respLine, &parsed); err != nil {
			t.Fatalf("failed to parse response JSON (%s): %v", string(respLine), err)
		}
		return parsed
	}

	// 1. Initialize message
	initResp := sendAndReceive(`{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}`)
	if initResp["id"] != float64(1) {
		t.Errorf("expected id 1, got %v", initResp["id"])
	}

	// 2. Safe tool call (read_file inside workspace)
	safeResp := sendAndReceive(`{"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "read_file", "arguments": {"path": "safe.txt"}}}`)
	res, ok := safeResp["result"].(map[string]interface{})
	if !ok || res["isError"] == true {
		t.Fatalf("expected safe tool call to succeed, got: %+v", safeResp)
	}

	// 3. Blocked tool call (traversal to ../.env)
	blockedEnvResp := sendAndReceive(`{"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "read_file", "arguments": {"path": "../.env"}}}`)
	bRes, ok := blockedEnvResp["result"].(map[string]interface{})
	if !ok || bRes["isError"] != true {
		t.Fatalf("expected ../.env tool call to be blocked with isError: true, got %+v", blockedEnvResp)
	}
	contentList := bRes["content"].([]interface{})
	firstContent := contentList[0].(map[string]interface{})
	reasonText := firstContent["text"].(string)
	if !strings.Contains(reasonText, "[MCP-JAIL POLICY BLOCK]") || !strings.Contains(reasonText, "filesystem_boundary") {
		t.Errorf("unexpected block message: %s", reasonText)
	}

	// 4. Blocked command guard (cat ~/.aws/credentials)
	blockedAwsResp := sendAndReceive(`{"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "echo_cmd", "arguments": {"command": "cat ~/.aws/credentials"}}}`)
	awsRes, ok := blockedAwsResp["result"].(map[string]interface{})
	if !ok || awsRes["isError"] != true {
		t.Fatalf("expected ~/.aws/credentials call to be blocked, got %+v", blockedAwsResp)
	}

	// 5. Secret leak test (leak_secret tool)
	// Response must be redacted before reaching host stdout
	leakResp := sendAndReceive(`{"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "leak_secret", "arguments": {}}}`)
	leakRes := leakResp["result"].(map[string]interface{})
	leakContent := leakRes["content"].([]interface{})[0].(map[string]interface{})["text"].(string)

	if strings.Contains(leakContent, "AKIA"+"IOSFODNN7EXAMPLE") {
		t.Fatalf("CRITICAL SECURITY LEAK: AWS Key was not scrubbed from stdout: %s", leakContent)
	}
	if !strings.Contains(leakContent, "[REDACTED_BY_MCP_JAIL:AWS_KEY]") && !strings.Contains(leakContent, "{{MCP_VAULT_TOKEN:AWS_KEY_") {
		t.Errorf("expected REDACTED tag or vault token in output, got: %s", leakContent)
	}
	if !strings.Contains(leakContent, "[REDACTED_BY_MCP_JAIL:AWS_SECRET]") && !strings.Contains(leakContent, "{{MCP_VAULT_TOKEN:AWS_SECRET_") {
		t.Errorf("expected REDACTED AWS_SECRET tag or vault token in output, got: %s", leakContent)
	}

	// 6. Test circuit breaker tripping (we've made 4 tool calls: #2, #3, #4, #5)
	// Call #6 should exceed MaxTotalCallsPerSession (set to 4)
	tripResp := sendAndReceive(`{"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": {"name": "read_file", "arguments": {"path": "safe2.txt"}}}`)
	tripRes, ok := tripResp["result"].(map[string]interface{})
	if !ok || tripRes["isError"] != true {
		t.Fatalf("expected 5th tool call to trip circuit breaker, got %+v", tripResp)
	}
	tripContent := tripRes["content"].([]interface{})[0].(map[string]interface{})["text"].(string)
	if !strings.Contains(tripContent, "rate_budget_total_calls") {
		t.Errorf("expected rate_budget_total_calls violation, got: %s", tripContent)
	}

	// Close HostIn to trigger clean shutdown of proxy
	_ = hostInW.Close()

	select {
	case err := <-proxyDone:
		if err != nil {
			t.Fatalf("proxy exited with error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("proxy timed out during shutdown")
	}

	_ = hostOutW.Close()

	// Assert server stderr never received forbidden calls
	if strings.Contains(hostErrBuf.String(), "SECURITY_FAILURE_SERVER_RECEIVED_FORBIDDEN_CALL") {
		t.Fatalf("SECURITY FAILURE: mock server received forbidden tool call!")
	}

	// 7. Verify SQLite flight recorder entries
	rec, err := recorder.NewRecorder(dbPath)
	if err != nil {
		t.Fatalf("failed to open recorder db: %v", err)
	}
	defer rec.Close()

	sess, err := rec.GetSession("e2e-session-123")
	if err != nil {
		t.Fatalf("failed to retrieve session: %v", err)
	}

	if sess.BlockedCalls < 3 {
		t.Errorf("expected at least 3 blocked calls, got %d", sess.BlockedCalls)
	}
	if sess.RedactedSecrets < 2 {
		t.Errorf("expected at least 2 redacted secrets, got %d", sess.RedactedSecrets)
	}

	events, err := rec.GetEvents(recorder.EventFilter{SessionID: "e2e-session-123"})
	if err != nil {
		t.Fatalf("failed to get events: %v", err)
	}
	if len(events) == 0 {
		t.Fatal("expected logged events in flight recorder, got 0")
	}

	hasRedactedEvent := false
	hasBlockedEvent := false
	for _, ev := range events {
		if ev.Action == recorder.ActionRedacted {
			hasRedactedEvent = true
		}
		if ev.Action == recorder.ActionBlocked {
			hasBlockedEvent = true
		}
	}
	if !hasRedactedEvent {
		t.Errorf("expected at least one event with action=redacted")
	}
	if !hasBlockedEvent {
		t.Errorf("expected at least one event with action=blocked")
	}
}
