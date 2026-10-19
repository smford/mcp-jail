package cli

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/smford/mcp-jail/internal/config"
	"github.com/smford/mcp-jail/internal/proxy"
	"github.com/spf13/cobra"
)

var (
	wrapConfig    string
	wrapDB        string
	wrapSessionID string
	wrapDryRun    bool
	wrapIsolate   bool
	wrapRemote    string
	wrapHeaders   []string
)

var wrapCmd = &cobra.Command{
	Use:   "wrap [flags] -- <command> [args...]",
	Short: "Wrap and monitor an MCP server command with security boundaries",
	Long: `Transparently proxy standard I/O streams of the target MCP server command or remote HTTP endpoint.
Enforces firewall policies, redacts credentials, and logs all events to SQLite.`,
	DisableFlagParsing: false,
	Args: func(cmd *cobra.Command, args []string) error {
		if wrapRemote == "" && len(args) == 0 {
			return fmt.Errorf("missing target MCP server command or --remote URL. Usage: mcp-jail wrap [flags] -- <command> [args...]")
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		// All logging in wrap mode must go to os.Stderr
		cfg, err := config.LoadConfig(wrapConfig)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[mcp-jail] config error: %v\n", err)
			os.Exit(1)
		}

		if wrapDryRun {
			cfg.Settings.DryRun = true
		}
		if wrapIsolate {
			cfg.Sandbox.Enabled = true
		}

		headersMap := make(map[string]string)
		for _, h := range wrapHeaders {
			parts := strings.SplitN(h, ":", 2)
			if len(parts) == 2 {
				headersMap[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			}
		}

		var targetCmd string
		var targetArgs []string
		if len(args) > 0 {
			targetCmd = args[0]
			if len(args) > 1 {
				targetArgs = args[1:]
			}
		}

		opts := proxy.Options{
			Config:    cfg,
			SessionID: wrapSessionID,
			DBPath:    wrapDB,
			DryRun:    cfg.Settings.DryRun,
			Command:   targetCmd,
			Args:      targetArgs,
			RemoteURL: wrapRemote,
			Headers:   headersMap,
			HostIn:    os.Stdin,
			HostOut:   os.Stdout,
			HostErr:   os.Stderr,
		}

		p, err := proxy.NewProxy(opts)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[mcp-jail] initialization error: %v\n", err)
			os.Exit(1)
		}

		exitCode, err := p.Run(context.Background())
		if err != nil {
			fmt.Fprintf(os.Stderr, "[mcp-jail] execution error: %v\n", err)
		}
		os.Exit(exitCode)
	},
}

func init() {
	wrapCmd.Flags().StringVarP(&wrapConfig, "config", "c", "", "Path to .mcp-jail.yaml config file (default: .mcp-jail.yaml in cwd)")
	wrapCmd.Flags().StringVar(&wrapDB, "db", "~/.mcp-jail/flight-recorder.db", "Path to SQLite flight recorder database")
	wrapCmd.Flags().StringVar(&wrapSessionID, "session-id", "", "Custom session identifier (default: generated UUID)")
	wrapCmd.Flags().BoolVar(&wrapDryRun, "dry-run", false, "Log violations to flight recorder without blocking calls")
	wrapCmd.Flags().BoolVar(&wrapIsolate, "isolate", false, "Enable OS-level subprocess sandboxing (sandbox-exec on macOS, bwrap on Linux)")
	wrapCmd.Flags().StringVar(&wrapRemote, "remote", "", "URL of upstream remote MCP server to bridge via stdio")
	wrapCmd.Flags().StringSliceVar(&wrapHeaders, "header", nil, "Custom HTTP header to send to remote server (e.g. --header 'Authorization: Bearer xxx')")
}
