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
var SupportedClients = []string{
	"claude",
	"cursor",
	"windsurf",
	"antigravity",
	"antigravity-cli",
	"antigravity-gui",
	"gemini",
	"gemini-cli",
	"gemini-gui",
}

// ServerConfig represents the MCP server configuration block in client JSON configs.
type ServerConfig struct {
	Command   string            `json:"command,omitempty"`
	Args      []string          `json:"args,omitempty"`
	Env       map[string]string `json:"env,omitempty"`
	ServerURL string            `json:"serverUrl,omitempty"`
	URL       string            `json:"url,omitempty"`
}

// ConfigFile represents a standard MCP client config containing mcpServers.
type ConfigFile struct {
	MCPServers map[string]ServerConfig `json:"mcpServers"`
	// Preserve any other top-level fields
	Other map[string]interface{} `json:"-"`
}

// GetDefaultConfigPaths resolves all default config paths for the requested client.
func GetDefaultConfigPaths(client string) ([]string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get user home directory: %w", err)
	}

	agyCLIPath := filepath.Join(home, ".gemini", "antigravity-cli", "mcp_config.json")
	agyGUIPath := filepath.Join(home, ".gemini", "config", "mcp_config.json")

	switch strings.ToLower(client) {
	case "claude":
		switch runtime.GOOS {
		case "darwin":
			return []string{filepath.Join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json")}, nil
		case "windows":
			appData := os.Getenv("APPDATA")
			if appData == "" {
				appData = filepath.Join(home, "AppData", "Roaming")
			}
			return []string{filepath.Join(appData, "Claude", "claude_desktop_config.json")}, nil
		default: // linux / bsd
			return []string{filepath.Join(home, ".config", "Claude", "claude_desktop_config.json")}, nil
		}

	case "cursor":
		return []string{filepath.Join(home, ".cursor", "mcp.json")}, nil

	case "windsurf":
		return []string{filepath.Join(home, ".codeium", "windsurf", "mcp_config.json")}, nil

	case "antigravity-cli", "gemini-cli", "agy-cli":
		return []string{agyCLIPath}, nil

	case "antigravity-gui", "gemini-gui", "agy-gui", "antigravity-ide":
		return []string{agyGUIPath}, nil

	case "antigravity", "gemini", "agy":
		var paths []string
		if _, err := os.Stat(agyCLIPath); err == nil {
			paths = append(paths, agyCLIPath)
		}
		if _, err := os.Stat(agyGUIPath); err == nil {
			paths = append(paths, agyGUIPath)
		}
		// If neither exists yet, return both so error or setup reports both locations
		if len(paths) == 0 {
			paths = append(paths, agyCLIPath, agyGUIPath)
		}
		return paths, nil

	default:
		return nil, fmt.Errorf("unsupported client %q (supported: %s)", client, strings.Join(SupportedClients, ", "))
	}
}

// GetDefaultConfigPath resolves the primary config path for single-target callers.
func GetDefaultConfigPath(client string) (string, error) {
	paths, err := GetDefaultConfigPaths(client)
	if err != nil {
		return "", err
	}
	if len(paths) == 0 {
		return "", fmt.Errorf("no config path found for %s", client)
	}
	return paths[0], nil
}

// InstallResult reports the result of wrapping servers in a specific config file.
type InstallResult struct {
	ConfigPath string
	BackupPath string
	Wrapped    []string
	Skipped    []string
}

// Install patches client config file(s) to wrap server commands with mcp-jail.
func Install(client, serverFilter, customPath string) ([]*InstallResult, error) {
	var paths []string
	if customPath != "" {
		paths = []string{customPath}
	} else {
		var err error
		paths, err = GetDefaultConfigPaths(client)
		if err != nil {
			return nil, err
		}
	}

	var results []*InstallResult
	var errs []string

	for _, cfgPath := range paths {
		res, err := installSingle(cfgPath, serverFilter, client)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", cfgPath, err))
			continue
		}
		results = append(results, res)
	}

	if len(results) == 0 && len(errs) > 0 {
		return nil, fmt.Errorf("install failed:\n  %s", strings.Join(errs, "\n  "))
	}

	return results, nil
}

func installSingle(cfgPath, serverFilter, client string) (*InstallResult, error) {
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("configuration file not found (ensure %s is installed)", client)
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
			res.Skipped = append(res.Skipped, sName+" (already wrapped)")
			continue
		}

		// Check for remote URL servers (serverUrl or url)
		if origCmd == "" {
			if _, hasURL := sMap["serverUrl"]; hasURL {
				res.Skipped = append(res.Skipped, sName+" (remote serverUrl)")
				continue
			}
			if _, hasURL := sMap["url"]; hasURL {
				res.Skipped = append(res.Skipped, sName+" (remote url)")
				continue
			}
			res.Skipped = append(res.Skipped, sName+" (no command defined)")
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

// UninstallResult reports unwrapped servers in a specific config file.
type UninstallResult struct {
	ConfigPath string
	Unwrapped  []string
	Skipped    []string
}

// Uninstall restores wrapped server commands in client config file(s) back to their original commands.
func Uninstall(client, serverFilter, customPath string) ([]*UninstallResult, error) {
	var paths []string
	if customPath != "" {
		paths = []string{customPath}
	} else {
		var err error
		paths, err = GetDefaultConfigPaths(client)
		if err != nil {
			return nil, err
		}
	}

	var results []*UninstallResult
	var errs []string

	for _, cfgPath := range paths {
		res, err := uninstallSingle(cfgPath, serverFilter, client)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", cfgPath, err))
			continue
		}
		results = append(results, res)
	}

	if len(results) == 0 && len(errs) > 0 {
		return nil, fmt.Errorf("uninstall failed:\n  %s", strings.Join(errs, "\n  "))
	}

	return results, nil
}

func uninstallSingle(cfgPath, serverFilter, client string) (*UninstallResult, error) {
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
