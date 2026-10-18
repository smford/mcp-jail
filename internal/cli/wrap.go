package cli

import (
	"context"
	"fmt"
	"os"

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
)

var wrapCmd = &cobra.Command{
	Use:   "wrap [flags] -- <command> [args...]",
	Short: "Wrap and monitor an MCP server command with security boundaries",
	Long: `Transparently proxy standard I/O streams of the target MCP server command.
Enforces firewall policies, redacts credentials, and logs all events to SQLite.`,
	DisableFlagParsing: false,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return fmt.Errorf("missing target MCP server command. Usage: mcp-jail wrap [flags] -- <command> [args...]")
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

		targetCmd := args[0]
		var targetArgs []string
		if len(args) > 1 {
			targetArgs = args[1:]
		}

		opts := proxy.Options{
			Config:    cfg,
			SessionID: wrapSessionID,
			DBPath:    wrapDB,
			DryRun:    cfg.Settings.DryRun,
			Command:   targetCmd,
			Args:      targetArgs,
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
}
