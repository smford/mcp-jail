package cli

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/smford/mcp-jail/internal/config"
	"github.com/smford/mcp-jail/internal/integrations"
	"github.com/smford/mcp-jail/internal/recorder"
	"github.com/spf13/cobra"
	_ "modernc.org/sqlite"
)

var doctorJSON bool

type CheckStatus string

const (
	StatusPass CheckStatus = "PASS"
	StatusWarn CheckStatus = "WARN"
	StatusFail CheckStatus = "FAIL"
	StatusInfo CheckStatus = "INFO"
)

type CheckItem struct {
	Category string      `json:"category"`
	Name     string      `json:"name"`
	Status   CheckStatus `json:"status"`
	Message  string      `json:"message"`
}

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Run comprehensive system diagnostics, server connectivity checks, and policy audits",
	Long: `Diagnoses your mcp-jail environment by validating:
  • AI client configurations (Antigravity, Claude, Cursor, Windsurf)
  • Reachability of remote MCP servers and availability of local CLI binaries
  • Flight recorder SQLite database integrity and permissions
  • Security policy syntax and directory boundaries
  • OS kernel sandbox capabilities (macOS Seatbelt, Linux Bubblewrap)`,
	RunE: func(cmd *cobra.Command, args []string) error {
		var checks []CheckItem

		// 1. Check AI Clients
		checks = append(checks, checkAIClients()...)

		// 2. Check Server Connectivity
		checks = append(checks, checkServers()...)

		// 3. Check SQLite Flight Recorder
		checks = append(checks, checkFlightRecorder()...)

		// 4. Check Security Policy
		checks = append(checks, checkPolicy()...)

		// 5. Check OS Sandboxing
		checks = append(checks, checkSandbox()...)

		outWriter := cmd.OutOrStdout()

		if doctorJSON {
			out, err := json.MarshalIndent(checks, "", "  ")
			if err != nil {
				return err
			}
			fmt.Fprintln(outWriter, string(out))
			return nil
		}

		// Print human-readable report
		fmt.Fprintln(outWriter, "🩺 mcp-jail Doctor: System & Environment Diagnostics")
		fmt.Fprintln(outWriter)

		currentCategory := ""
		passCount, warnCount, failCount := 0, 0, 0

		for _, c := range checks {
			if c.Category != currentCategory {
				currentCategory = c.Category
				fmt.Fprintf(outWriter, "[%s]\n", currentCategory)
			}

			icon := "•"
			switch c.Status {
			case StatusPass:
				icon = "\033[1;32m✓\033[0m"
				passCount++
			case StatusWarn:
				icon = "\033[1;33m!\033[0m"
				warnCount++
			case StatusFail:
				icon = "\033[1;31m✗\033[0m"
				failCount++
			case StatusInfo:
				icon = "\033[1;34m•\033[0m"
			}

			fmt.Fprintf(outWriter, "  %s %s: %s\n", icon, c.Name, c.Message)
		}

		fmt.Fprintln(outWriter)
		if failCount > 0 {
			fmt.Fprintf(outWriter, "\033[1;31mDiagnostics completed with %d failure(s), %d warning(s), %d passed.\033[0m\n",
				failCount, warnCount, passCount)
		} else if warnCount > 0 {
			fmt.Fprintf(outWriter, "\033[1;33mDiagnostics completed with %d warning(s), %d passed.\033[0m\n",
				warnCount, passCount)
		} else {
			fmt.Fprintf(outWriter, "\033[1;32mAll core systems operational (%d checks passed).\033[0m\n", passCount)
		}

		return nil
	},
}

func checkAIClients() []CheckItem {
	var items []CheckItem
	clients := []struct {
		name string
		id   string
	}{
		{"Antigravity CLI", "antigravity-cli"},
		{"Antigravity GUI", "antigravity-gui"},
		{"Claude Desktop", "claude"},
		{"Cursor IDE", "cursor"},
		{"Windsurf IDE", "windsurf"},
	}

	for _, c := range clients {
		paths, err := integrations.GetDefaultConfigPaths(c.id)
		if err != nil || len(paths) == 0 {
			continue
		}

		cfgPath := paths[0]
		data, err := os.ReadFile(cfgPath)
		if err != nil {
			if os.IsNotExist(err) {
				items = append(items, CheckItem{
					Category: "AI Clients",
					Name:     c.name,
					Status:   StatusInfo,
					Message:  fmt.Sprintf("not installed / config not found at %s", cfgPath),
				})
			} else {
				items = append(items, CheckItem{
					Category: "AI Clients",
					Name:     c.name,
					Status:   StatusFail,
					Message:  fmt.Sprintf("error reading config: %v", err),
				})
			}
			continue
		}

		var raw map[string]interface{}
		if err := json.Unmarshal(data, &raw); err != nil {
			items = append(items, CheckItem{
				Category: "AI Clients",
				Name:     c.name,
				Status:   StatusFail,
				Message:  fmt.Sprintf("invalid JSON in %s: %v", cfgPath, err),
			})
			continue
		}

		serversRaw, _ := raw["mcpServers"].(map[string]interface{})
		wrappedCount := 0
		for _, sVal := range serversRaw {
			if sMap, ok := sVal.(map[string]interface{}); ok {
				if cmd, _ := sMap["command"].(string); cmd == "mcp-jail" {
					wrappedCount++
				}
			}
		}

		items = append(items, CheckItem{
			Category: "AI Clients",
			Name:     c.name,
			Status:   StatusPass,
			Message:  fmt.Sprintf("config valid (%s, %d server(s), %d protected)", cfgPath, len(serversRaw), wrappedCount),
		})
	}

	return items
}

func checkServers() []CheckItem {
	var items []CheckItem
	servers, err := integrations.ListServers("", "")
	if err != nil || len(servers) == 0 {
		return items
	}

	client := &http.Client{Timeout: 3 * time.Second}

	for _, s := range servers {
		serverLabel := fmt.Sprintf("%s (%s)", s.Name, s.Client)

		// Check remote URL servers
		if strings.HasPrefix(s.Target, "http://") || strings.HasPrefix(s.Target, "https://") {
			urlStr := strings.TrimSuffix(s.Target, " (remote)")
			start := time.Now()
			resp, err := client.Post(urlStr, "application/json", strings.NewReader(`{"jsonrpc":"2.0","method":"ping"}`))
			latency := time.Since(start).Milliseconds()

			if err != nil {
				items = append(items, CheckItem{
					Category: "Configured Servers",
					Name:     serverLabel,
					Status:   StatusWarn,
					Message:  fmt.Sprintf("remote endpoint unreachable (%s: %v)", urlStr, err),
				})
			} else {
				_ = resp.Body.Close()
				items = append(items, CheckItem{
					Category: "Configured Servers",
					Name:     serverLabel,
					Status:   StatusPass,
					Message:  fmt.Sprintf("remote HTTP reachable (%s, %dms)", urlStr, latency),
				})
			}
			continue
		}

		// Check local command binaries
		cmdName := s.Command
		if cmdName == "mcp-jail" && len(s.Args) > 0 {
			// Find actual target
			for i, a := range s.Args {
				if a == "--" && i+1 < len(s.Args) {
					cmdName = s.Args[i+1]
					break
				}
			}
		}

		if cmdName != "" && cmdName != "mcp-jail" {
			_, err := exec.LookPath(cmdName)
			if err != nil {
				items = append(items, CheckItem{
					Category: "Configured Servers",
					Name:     serverLabel,
					Status:   StatusWarn,
					Message:  fmt.Sprintf("binary %q not found in PATH", cmdName),
				})
			} else {
				items = append(items, CheckItem{
					Category: "Configured Servers",
					Name:     serverLabel,
					Status:   StatusPass,
					Message:  fmt.Sprintf("local binary %q found in PATH", cmdName),
				})
			}
		}
	}

	return items
}

func checkFlightRecorder() []CheckItem {
	var items []CheckItem
	dbPath := recorder.ExpandPath("~/.mcp-jail/flight-recorder.db")

	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		items = append(items, CheckItem{
			Category: "Flight Recorder",
			Name:     "SQLite Database",
			Status:   StatusFail,
			Message:  fmt.Sprintf("directory %s not writable: %v", dir, err),
		})
		return items
	}

	db, err := sql.Open("sqlite", dbPath+"?_pragma=busy_timeout(2000)")
	if err != nil {
		items = append(items, CheckItem{
			Category: "Flight Recorder",
			Name:     "SQLite Database",
			Status:   StatusFail,
			Message:  fmt.Sprintf("cannot open database: %v", err),
		})
		return items
	}
	defer db.Close()

	var integrityResult string
	err = db.QueryRow("PRAGMA integrity_check").Scan(&integrityResult)
	if err != nil || integrityResult != "ok" {
		items = append(items, CheckItem{
			Category: "Flight Recorder",
			Name:     "SQLite Database",
			Status:   StatusWarn,
			Message:  fmt.Sprintf("integrity warning: %v", integrityResult),
		})
	} else {
		items = append(items, CheckItem{
			Category: "Flight Recorder",
			Name:     "SQLite Database",
			Status:   StatusPass,
			Message:  fmt.Sprintf("healthy (%s, integrity %s)", dbPath, integrityResult),
		})
	}

	return items
}

func checkPolicy() []CheckItem {
	var items []CheckItem
	policyPath := ".mcp-jail.yaml"

	if _, err := os.Stat(policyPath); err != nil {
		items = append(items, CheckItem{
			Category: "Security Policy",
			Name:     "Policy Configuration",
			Status:   StatusInfo,
			Message:  "no local .mcp-jail.yaml found (run 'mcp-jail init' to create one)",
		})
		return items
	}

	cfg, err := config.LoadConfig(policyPath)
	if err != nil {
		items = append(items, CheckItem{
			Category: "Security Policy",
			Name:     "Policy Configuration",
			Status:   StatusFail,
			Message:  fmt.Sprintf("policy syntax error: %v", err),
		})
		return items
	}

	// Check allowed roots
	var missingRoots []string
	for _, root := range cfg.Filesystem.AllowedRoots {
		if _, err := os.Stat(root); err != nil {
			missingRoots = append(missingRoots, root)
		}
	}

	if len(missingRoots) > 0 {
		items = append(items, CheckItem{
			Category: "Security Policy",
			Name:     "Filesystem Roots",
			Status:   StatusWarn,
			Message:  fmt.Sprintf("missing allowed roots: %s", strings.Join(missingRoots, ", ")),
		})
	} else {
		items = append(items, CheckItem{
			Category: "Security Policy",
			Name:     "Policy Configuration",
			Status:   StatusPass,
			Message:  fmt.Sprintf("valid policy (%d allowed roots, %d denied tools, %d arg rules)",
				len(cfg.Filesystem.AllowedRoots), len(cfg.Tools.Denied), len(cfg.Tools.Rules)),
		})
	}

	return items
}

func checkSandbox() []CheckItem {
	var items []CheckItem

	switch runtime.GOOS {
	case "darwin":
		if _, err := exec.LookPath("/usr/bin/sandbox-exec"); err == nil {
			items = append(items, CheckItem{
				Category: "OS Sandboxing",
				Name:     "macOS Seatbelt",
				Status:   StatusPass,
				Message:  "available (/usr/bin/sandbox-exec, ready for --isolate)",
			})
		} else {
			items = append(items, CheckItem{
				Category: "OS Sandboxing",
				Name:     "macOS Seatbelt",
				Status:   StatusWarn,
				Message:  "sandbox-exec not found",
			})
		}
	case "linux":
		if path, err := exec.LookPath("bwrap"); err == nil {
			items = append(items, CheckItem{
				Category: "OS Sandboxing",
				Name:     "Linux Bubblewrap",
				Status:   StatusPass,
				Message:  fmt.Sprintf("available (%s, ready for --isolate)", path),
			})
		} else {
			items = append(items, CheckItem{
				Category: "OS Sandboxing",
				Name:     "Linux Bubblewrap",
				Status:   StatusWarn,
				Message:  "bubblewrap (bwrap) not installed in PATH",
			})
		}
	default:
		items = append(items, CheckItem{
			Category: "OS Sandboxing",
			Name:     "OS Isolation",
			Status:   StatusInfo,
			Message:  fmt.Sprintf("OS %s uses software proxy firewall boundaries", runtime.GOOS),
		})
	}

	return items
}

func init() {
	doctorCmd.Flags().BoolVar(&doctorJSON, "json", false, "Output diagnostics in JSON format")
}
