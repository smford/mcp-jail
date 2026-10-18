package integrations

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// SupportedClients lists valid client target names.
var SupportedClients = []string{"claude", "cursor", "windsurf"}

// ServerConfig represents the MCP server configuration block in client JSON configs.
type ServerConfig struct {
	Command string            `json:"command"`
	Args    []string          `json:"args,omitempty"`
	Env     map[string]string `json:"env,omitempty"`
}

// ConfigFile represents a standard MCP client config containing mcpServers.
type ConfigFile struct {
	MCPServers map[string]ServerConfig `json:"mcpServers"`
	// Preserve any other top-level fields
	Other map[string]interface{} `json:"-"`
}

// GetDefaultConfigPath resolves the default config path for the requested client.
func GetDefaultConfigPath(client string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get user home directory: %w", err)
	}

	switch strings.ToLower(client) {
	case "claude":
		switch runtime.GOOS {
		case "darwin":
			return filepath.Join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json"), nil
		case "windows":
			appData := os.Getenv("APPDATA")
			if appData == "" {
				appData = filepath.Join(home, "AppData", "Roaming")
			}
			return filepath.Join(appData, "Claude", "claude_desktop_config.json"), nil
		default: // linux / bsd
			return filepath.Join(home, ".config", "Claude", "claude_desktop_config.json"), nil
		}

	case "cursor":
		return filepath.Join(home, ".cursor", "mcp.json"), nil

	case "windsurf":
		return filepath.Join(home, ".codeium", "windsurf", "mcp_config.json"), nil

	default:
		return "", fmt.Errorf("unsupported client %q (supported: %s)", client, strings.Join(SupportedClients, ", "))
	}
}

// InstallResult reports the result of wrapping servers.
type InstallResult struct {
	ConfigPath string
	BackupPath string
	Wrapped    []string
	Skipped    []string
}

// Install patches the client config to wrap server commands with mcp-jail.
func Install(client, serverFilter, customPath string) (*InstallResult, error) {
	cfgPath := customPath
	if cfgPath == "" {
		var err error
		cfgPath, err = GetDefaultConfigPath(client)
		if err != nil {
			return nil, err
		}
	}

	data, err := os.ReadFile(cfgPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("configuration file not found at %s: ensure %s is installed", cfgPath, client)
		}
		return nil, fmt.Errorf("failed to read %s: %w", cfgPath, err)
	}

	// Backup original file
	bakPath := cfgPath + ".mcp-jail.bak"
	if err := os.WriteFile(bakPath, data, 0600); err != nil {
		return nil, fmt.Errorf("failed to create backup at %s: %w", bakPath, err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("failed to parse JSON from %s: %w", cfgPath, err)
	}

	serversRaw, ok := raw["mcpServers"].(map[string]interface{})
	if !ok || len(serversRaw) == 0 {
		return nil, fmt.Errorf("no 'mcpServers' found in %s", cfgPath)
	}

	res := &InstallResult{
		ConfigPath: cfgPath,
		BackupPath: bakPath,
	}

	for sName, sVal := range serversRaw {
		if serverFilter != "" && sName != serverFilter {
			continue
		}

		sMap, ok := sVal.(map[string]interface{})
		if !ok {
			continue
		}

		origCmd, _ := sMap["command"].(string)
		if origCmd == "mcp-jail" {
			res.Skipped = append(res.Skipped, sName)
			continue
		}

		var origArgs []string
		if argsArr, ok := sMap["args"].([]interface{}); ok {
			for _, a := range argsArr {
				if str, ok := a.(string); ok {
					origArgs = append(origArgs, str)
				}
			}
		}

		// Wrap with mcp-jail wrap -- <cmd> <args...>
		newArgs := []string{"wrap", "--", origCmd}
		newArgs = append(newArgs, origArgs...)

		sMap["command"] = "mcp-jail"
		sMap["args"] = newArgs
		res.Wrapped = append(res.Wrapped, sName)
	}

	out, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal updated config: %w", err)
	}

	if err := os.WriteFile(cfgPath, out, 0644); err != nil {
		return nil, fmt.Errorf("failed to write updated config to %s: %w", cfgPath, err)
	}

	return res, nil
}

// UninstallResult reports unwrapped servers.
type UninstallResult struct {
	ConfigPath string
	Unwrapped  []string
	Skipped    []string
}

// Uninstall restores wrapped server commands in the client config back to their original commands.
func Uninstall(client, serverFilter, customPath string) (*UninstallResult, error) {
	cfgPath := customPath
	if cfgPath == "" {
		var err error
		cfgPath, err = GetDefaultConfigPath(client)
		if err != nil {
			return nil, err
		}
	}

	data, err := os.ReadFile(cfgPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", cfgPath, err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("failed to parse JSON from %s: %w", cfgPath, err)
	}

	serversRaw, ok := raw["mcpServers"].(map[string]interface{})
	if !ok || len(serversRaw) == 0 {
		return nil, fmt.Errorf("no 'mcpServers' found in %s", cfgPath)
	}

	res := &UninstallResult{
		ConfigPath: cfgPath,
	}

	for sName, sVal := range serversRaw {
		if serverFilter != "" && sName != serverFilter {
			continue
		}

		sMap, ok := sVal.(map[string]interface{})
		if !ok {
			continue
		}

		cmd, _ := sMap["command"].(string)
		if cmd != "mcp-jail" {
			res.Skipped = append(res.Skipped, sName)
			continue
		}

		var args []string
		if argsArr, ok := sMap["args"].([]interface{}); ok {
			for _, a := range argsArr {
				if str, ok := a.(string); ok {
					args = append(args, str)
				}
			}
		}

		// Find separator "--"
		dashIdx := -1
		for i, a := range args {
			if a == "--" {
				dashIdx = i
				break
			}
		}

		if dashIdx != -1 && dashIdx+1 < len(args) {
			sMap["command"] = args[dashIdx+1]
			sMap["args"] = args[dashIdx+2:]
			res.Unwrapped = append(res.Unwrapped, sName)
		} else {
			res.Skipped = append(res.Skipped, sName)
		}
	}

	out, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal updated config: %w", err)
	}

	if err := os.WriteFile(cfgPath, out, 0644); err != nil {
		return nil, fmt.Errorf("failed to write updated config to %s: %w", cfgPath, err)
	}

	return res, nil
}
