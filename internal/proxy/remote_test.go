package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/smford/mcp-jail/internal/config"
)

func TestProxy_RunRemote(t *testing.T) {
	// Upstream mock MCP HTTP server
	upstreamCalls := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls++
		if r.Header.Get("Authorization") != "Bearer test-secret-token" {
			t.Errorf("missing or incorrect Authorization header: %s", r.Header.Get("Authorization"))
		}

		var req struct {
			ID     interface{} `json:"id"`
			Method string      `json:"method"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)

		w.Header().Set("Content-Type", "application/json")
		if req.Method == "tools/list" {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      req.ID,
				"result": map[string]interface{}{
					"tools": []map[string]interface{}{
						{"name": "test_tool"},
					},
				},
			})
			return
		}

		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      req.ID,
			"result": map[string]interface{}{
				"status": "success",
			},
		})
	}))
	defer ts.Close()

	cfg := &config.Config{
		Tools: config.ToolsConfig{
			Denied: []string{"^blocked_tool$"},
		},
		Scrubber: config.ScrubberConfig{
			Enabled: true,
		},
	}

	inBuf := &bytes.Buffer{}
	outBuf := &bytes.Buffer{}
	errBuf := &bytes.Buffer{}

	// Send an allowed tool call followed by a blocked tool call
	inBuf.WriteString(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}` + "\n")
	inBuf.WriteString(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"blocked_tool","arguments":{}}}` + "\n")

	opts := Options{
		Config:    cfg,
		SessionID: "test-remote-session",
		DBPath:    ":memory:",
		RemoteURL: ts.URL,
		Headers: map[string]string{
			"Authorization": "Bearer test-secret-token",
		},
		HostIn:  inBuf,
		HostOut: outBuf,
		HostErr: errBuf,
	}

	p, err := NewProxy(opts)
	if err != nil {
		t.Fatalf("NewProxy failed: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	exitCode, err := p.Run(ctx)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("expected exit code 0, got %d", exitCode)
	}

	// Verify upstream was only called once (for tools/list, blocked_tool was blocked locally)
	if upstreamCalls != 1 {
		t.Errorf("expected upstream to be called 1 time, got %d", upstreamCalls)
	}

	outStr := outBuf.String()
	if !strings.Contains(outStr, `"tools"`) {
		t.Errorf("expected tools/list response in output, got %s", outStr)
	}
	if !strings.Contains(outStr, `[MCP-JAIL POLICY BLOCK]`) {
		t.Errorf("expected blocked response in output, got %s", outStr)
	}
}
