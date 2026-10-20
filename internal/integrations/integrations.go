package integrations

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
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
	"workspace",
	"local",
	"project",
}

// WorkspaceConfigCandidates lists relative paths checked for local repository/workspace MCP configurations.
var WorkspaceConfigCandidates = []string{
	filepath.Join(".cursor", "mcp.json"),
	filepath.Join(".vscode", "mcp.json"),
	"mcp.json",
	".mcp.json",
}

// GetWorkspaceConfigPaths checks the current working directory for local project workspace MCP config files.
func GetWorkspaceConfigPaths() []string {
	var found []string
	for _, candidate := range WorkspaceConfigCandidates {
		if _, err := os.Stat(candidate); err == nil {
			found = append(found, candidate)
		}
	}
	return found
}

// StandardClients lists distinct client configurations scanned by default.
var StandardClients = []string{
	"antigravity-cli",
	"antigravity-gui",
	"claude",
	"cursor",
	"windsurf",
}

// ServerInfo reports details and protection status of an installed MCP server.
type ServerInfo struct {
	Client     string   `json:"client"`
	ConfigPath string   `json:"config_path"`
	Name       string   `json:"name"`
	Status     string   `json:"status"` // "Protected", "Unprotected", "Remote URL", "Empty"
	Command    string   `json:"command,omitempty"`
	Args       []string `json:"args,omitempty"`
	Target     string   `json:"target"`
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

	case "workspace", "local", "project":
		ws := GetWorkspaceConfigPaths()
		if len(ws) > 0 {
			return ws, nil
		}
		return []string{filepath.Join(".cursor", "mcp.json")}, nil

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
			var remoteURL string
			if u, hasURL := sMap["serverUrl"].(string); hasURL && u != "" {
				remoteURL = u
			} else if u, hasURL := sMap["url"].(string); hasURL && u != "" {
				remoteURL = u
			}

			if remoteURL != "" {
				wrapArgs := []string{"wrap", "--remote", remoteURL}
				if headersMap, ok := sMap["headers"].(map[string]interface{}); ok {
					for hName, hVal := range headersMap {
						if hStr, ok := hVal.(string); ok {
							wrapArgs = append(wrapArgs, "--header", fmt.Sprintf("%s: %s", hName, hStr))
						}
					}
				}

				// Preserve original remote config for uninstall restoration
				sMap["_original_serverUrl"] = remoteURL
				if h, hasHeaders := sMap["headers"]; hasHeaders {
					sMap["_original_headers"] = h
					delete(sMap, "headers")
				}
				delete(sMap, "serverUrl")
				delete(sMap, "url")

				sMap["command"] = "mcp-jail"
				sMap["args"] = wrapArgs
				res.Wrapped = append(res.Wrapped, sName+" (remote "+remoteURL+")")
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

		// Restore remote server if it was wrapped with --remote
		if origURL, ok := sMap["_original_serverUrl"].(string); ok && origURL != "" {
			sMap["serverUrl"] = origURL
			delete(sMap, "_original_serverUrl")
			if origH, hasH := sMap["_original_headers"]; hasH {
				sMap["headers"] = origH
				delete(sMap, "_original_headers")
			}
			delete(sMap, "command")
			delete(sMap, "args")
			res.Unwrapped = append(res.Unwrapped, sName+" (restored remote "+origURL+")")
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

// ListServers discovers and inspects MCP servers across supported AI clients.
func ListServers(clientFilter, customPath string) ([]*ServerInfo, error) {
	if customPath != "" {
		return listServersFromConfig(customPath, "custom")
	}

	var clientsToScan []string
	if clientFilter == "" || strings.ToLower(clientFilter) == "all" {
		clientsToScan = StandardClients
	} else {
		filter := strings.ToLower(clientFilter)
		switch filter {
		case "antigravity", "gemini", "agy":
			clientsToScan = []string{"antigravity-cli", "antigravity-gui"}
		default:
			clientsToScan = []string{filter}
		}
	}

	var allServers []*ServerInfo
	var errs []string

	for _, client := range clientsToScan {
		paths, err := GetDefaultConfigPaths(client)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", client, err))
			continue
		}

		for _, p := range paths {
			if _, err := os.Stat(p); err != nil {
				// If a specific client was requested, report that it was not found
				if clientFilter != "" && clientFilter != "all" {
					errs = append(errs, fmt.Sprintf("%s (%s): file not found", client, p))
				}
				continue
			}

			servers, err := listServersFromConfig(p, client)
			if err != nil {
				errs = append(errs, fmt.Sprintf("%s: %v", p, err))
				continue
			}
			allServers = append(allServers, servers...)
		}
	}

	if len(allServers) == 0 && len(errs) > 0 {
		return nil, fmt.Errorf("%s", strings.Join(errs, "\n"))
	}

	// Auto-discover local workspace configurations when scanning all clients
	if clientFilter == "" || strings.ToLower(clientFilter) == "all" {
		seenPaths := make(map[string]bool)
		for _, s := range allServers {
			if abs, err := filepath.Abs(s.ConfigPath); err == nil {
				seenPaths[abs] = true
			}
		}
		wsPaths := GetWorkspaceConfigPaths()
		for _, p := range wsPaths {
			abs, err := filepath.Abs(p)
			if err == nil && seenPaths[abs] {
				continue
			}
			servers, err := listServersFromConfig(p, "workspace")
			if err == nil && len(servers) > 0 {
				allServers = append(allServers, servers...)
				seenPaths[abs] = true
			}
		}
	}

	return allServers, nil
}

func listServersFromConfig(cfgPath, clientName string) ([]*ServerInfo, error) {
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		return nil, err
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("invalid json in %s: %w", cfgPath, err)
	}

	serversRaw, ok := raw["mcpServers"].(map[string]interface{})
	if !ok || len(serversRaw) == 0 {
		serversRaw, ok = raw["servers"].(map[string]interface{})
		if !ok || len(serversRaw) == 0 {
			return nil, nil
		}
	}

	var list []*ServerInfo
	for sName, sVal := range serversRaw {
		sMap, ok := sVal.(map[string]interface{})
		if !ok {
			continue
		}

		info := &ServerInfo{
			Client:     clientName,
			ConfigPath: cfgPath,
			Name:       sName,
		}

		cmd, _ := sMap["command"].(string)
		var args []string
		if argsRaw, ok := sMap["args"].([]interface{}); ok {
			for _, a := range argsRaw {
				if s, ok := a.(string); ok {
					args = append(args, s)
				}
			}
		}

		info.Command = cmd
		info.Args = args

		serverURL, _ := sMap["serverUrl"].(string)
		if serverURL == "" {
			serverURL, _ = sMap["url"].(string)
		}

		if cmd == "mcp-jail" {
			info.Status = "Protected"
			// Check if wrapping a remote URL via --remote
			var remoteURL string
			for i, a := range args {
				if a == "--remote" && i+1 < len(args) {
					remoteURL = args[i+1]
					break
				}
			}
			if remoteURL != "" {
				info.Target = remoteURL + " (remote)"
			} else {
				targetCmd, targetArgs := extractTargetFromWrap(args)
				if targetCmd != "" {
					if len(targetArgs) > 0 {
						info.Target = targetCmd + " " + strings.Join(targetArgs, " ")
					} else {
						info.Target = targetCmd
					}
				} else {
					info.Target = "mcp-jail " + strings.Join(args, " ")
				}
			}
		} else if cmd != "" {
			info.Status = "Unprotected"
			if len(args) > 0 {
				info.Target = cmd + " " + strings.Join(args, " ")
			} else {
				info.Target = cmd
			}
		} else if serverURL != "" {
			info.Status = "Unprotected (Remote URL)"
			info.Target = serverURL
		} else {
			info.Status = "Empty"
			info.Target = "(no command/url)"
		}

		list = append(list, info)
	}

	sort.Slice(list, func(i, j int) bool {
		if list[i].Client != list[j].Client {
			return list[i].Client < list[j].Client
		}
		return list[i].Name < list[j].Name
	})

	return list, nil
}

func extractTargetFromWrap(args []string) (string, []string) {
	for i, arg := range args {
		if arg == "--" && i+1 < len(args) {
			return args[i+1], args[i+2:]
		}
	}
	return "", nil
}
