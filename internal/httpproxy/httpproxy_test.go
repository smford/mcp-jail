package httpproxy

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/smford/mcp-jail/internal/config"
	"github.com/smford/mcp-jail/internal/recorder"
)

func TestHTTPProxyHealthAndBlock(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "mcp-jail-http-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	dbPath := filepath.Join(tempDir, "test.db")
	rec, err := recorder.NewRecorder(dbPath)
	if err != nil {
		t.Fatalf("failed to create recorder: %v", err)
	}
	defer rec.Close()

	// Mock upstream MCP server
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"upstream response"}]}}`))
	}))
	defer upstream.Close()

	cfg := config.DefaultConfig()
	proxyServer, err := NewServer(upstream.URL, cfg, rec)
	if err != nil {
		t.Fatalf("failed to create proxy server: %v", err)
	}

	// 1. Test /healthz
	reqHealth := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	recHealth := httptest.NewRecorder()
	proxyServer.ServeHTTP(recHealth, reqHealth)

	if recHealth.Code != http.StatusOK {
		t.Errorf("expected 200 OK from /healthz, got %d", recHealth.Code)
	}
	if !strings.Contains(recHealth.Body.String(), `"status":"ok"`) {
		t.Errorf("expected status:ok in healthz response, got: %s", recHealth.Body.String())
	}

	// 2. Test blocked tool call (format_disk)
	blockedBody := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"format_disk","arguments":{}}}`
	reqBlocked := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(blockedBody))
	recBlocked := httptest.NewRecorder()
	proxyServer.ServeHTTP(recBlocked, reqBlocked)

	if !strings.Contains(recBlocked.Body.String(), `"isError":true`) {
		t.Errorf("expected blocked response with isError:true, got: %s", recBlocked.Body.String())
	}
}
