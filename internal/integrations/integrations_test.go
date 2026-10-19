package integrations

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestIntegrations_InstallAndUninstall(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "claude_desktop_config.json")

	initialJSON := `{
  "mcpServers": {
    "sqlite": {
      "command": "uvx",
      "args": ["mcp-server-sqlite", "--db-path", "test.db"]
    },
    "fetch": {
      "command": "uvx",
      "args": ["mcp-server-fetch"]
    },
    "remote_service": {
      "serverUrl": "https://remote.example.com/mcp"
    }
  }
}`

	if err := os.WriteFile(configPath, []byte(initialJSON), 0644); err != nil {
		t.Fatalf("failed to write test config: %v", err)
	}

	// 1. Install mcp-jail
	results, err := Install("claude", "", configPath)
	if err != nil {
		t.Fatalf("Install failed: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	res := results[0]

	if len(res.Wrapped) != 2 {
		t.Fatalf("expected 2 wrapped servers, got %d", len(res.Wrapped))
	}
	if len(res.Skipped) != 1 {
		t.Fatalf("expected 1 skipped remote server, got %d", len(res.Skipped))
	}

	// Verify backup exists
	if _, err := os.Stat(res.BackupPath); err != nil {
		t.Fatalf("expected backup file to exist: %v", err)
	}

	// Verify file content was wrapped
	updatedData, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("failed to read updated config: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(updatedData, &parsed); err != nil {
		t.Fatalf("failed to unmarshal updated config: %v", err)
	}

	servers := parsed["mcpServers"].(map[string]interface{})
	sqlite := servers["sqlite"].(map[string]interface{})
	if sqlite["command"] != "mcp-jail" {
		t.Errorf("expected command 'mcp-jail', got %s", sqlite["command"])
	}

	// Idempotency: calling Install again should skip already wrapped servers
	results2, err := Install("claude", "", configPath)
	if err != nil {
		t.Fatalf("Second install failed: %v", err)
	}
	res2 := results2[0]
	if len(res2.Wrapped) != 0 || len(res2.Skipped) != 3 {
		t.Errorf("expected 0 wrapped and 3 skipped on re-install, got %d wrapped, %d skipped", len(res2.Wrapped), len(res2.Skipped))
	}

	// 2. Uninstall mcp-jail
	unresults, err := Uninstall("claude", "", configPath)
	if err != nil {
		t.Fatalf("Uninstall failed: %v", err)
	}
	unres := unresults[0]
	if len(unres.Unwrapped) != 2 {
		t.Fatalf("expected 2 unwrapped servers, got %d", len(unres.Unwrapped))
	}

	// Verify restored command
	restoredData, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("failed to read restored config: %v", err)
	}
	var restoredParsed map[string]interface{}
	if err := json.Unmarshal(restoredData, &restoredParsed); err != nil {
		t.Fatalf("failed to unmarshal restored config: %v", err)
	}
	restoredServers := restoredParsed["mcpServers"].(map[string]interface{})
	restoredSqlite := restoredServers["sqlite"].(map[string]interface{})
	if restoredSqlite["command"] != "uvx" {
		t.Errorf("expected restored command 'uvx', got %s", restoredSqlite["command"])
	}
}

func TestIntegrations_AntigravityPaths(t *testing.T) {
	paths, err := GetDefaultConfigPaths("antigravity")
	if err != nil {
		t.Fatalf("failed to get antigravity paths: %v", err)
	}
	if len(paths) == 0 {
		t.Fatal("expected at least 1 path for antigravity")
	}

	cliPaths, err := GetDefaultConfigPaths("antigravity-cli")
	if err != nil || len(cliPaths) != 1 {
		t.Fatalf("expected 1 path for antigravity-cli, got %v (err: %v)", cliPaths, err)
	}
	if filepath.Base(cliPaths[0]) != "mcp_config.json" {
		t.Errorf("expected mcp_config.json, got %s", cliPaths[0])
	}

	guiPaths, err := GetDefaultConfigPaths("antigravity-gui")
	if err != nil || len(guiPaths) != 1 {
		t.Fatalf("expected 1 path for antigravity-gui, got %v (err: %v)", guiPaths, err)
	}
	if filepath.Base(guiPaths[0]) != "mcp_config.json" {
		t.Errorf("expected mcp_config.json, got %s", guiPaths[0])
	}
}

func TestIntegrations_ListServers(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "mcp.json")

	content := `{
  "mcpServers": {
    "wrapped-tool": {
      "command": "mcp-jail",
      "args": ["wrap", "--config", ".mcp-jail.yaml", "--", "node", "server.js"]
    },
    "raw-tool": {
      "command": "npx",
      "args": ["-y", "my-server"]
    },
    "remote-tool": {
      "serverUrl": "https://api.example.com/mcp"
    }
  }
}`
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test config: %v", err)
	}

	servers, err := ListServers("", configPath)
	if err != nil {
		t.Fatalf("ListServers failed: %v", err)
	}

	if len(servers) != 3 {
		t.Fatalf("expected 3 servers, got %d", len(servers))
	}

	serverMap := make(map[string]*ServerInfo)
	for _, s := range servers {
		serverMap[s.Name] = s
	}

	wrapped := serverMap["wrapped-tool"]
	if wrapped == nil || wrapped.Status != "Protected" {
		t.Errorf("expected wrapped-tool to be Protected, got %+v", wrapped)
	}
	if wrapped.Target != "node server.js" {
		t.Errorf("expected target 'node server.js', got %q", wrapped.Target)
	}

	raw := serverMap["raw-tool"]
	if raw == nil || raw.Status != "Unprotected" {
		t.Errorf("expected raw-tool to be Unprotected, got %+v", raw)
	}
	if raw.Target != "npx -y my-server" {
		t.Errorf("expected target 'npx -y my-server', got %q", raw.Target)
	}

	remote := serverMap["remote-tool"]
	if remote == nil || remote.Status != "Remote URL" {
		t.Errorf("expected remote-tool to be Remote URL, got %+v", remote)
	}
	if remote.Target != "https://api.example.com/mcp" {
		t.Errorf("expected target 'https://api.example.com/mcp', got %q", remote.Target)
	}
}
