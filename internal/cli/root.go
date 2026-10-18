package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

var rootCmd = &cobra.Command{
	Use:   "mcp-jail",
	Short: "Zero-CGO local firewall and flight-recorder proxy for Model Context Protocol (MCP) servers",
	Long: `mcp-jail sits transparently between an AI host agent (Claude Code, Cursor, Antigravity)
and local MCP servers to enforce filesystem boundaries, guard against dangerous shell commands,
prevent runaway agent rate/budget loops, and redact outbound credentials.`,
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number and build metadata of mcp-jail",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("mcp-jail %s (commit: %s, date: %s)\n", version, commit, date)
	},
}

// SetVersion sets the build metadata and updates rootCmd.Version.
func SetVersion(v, c, d string) {
	if v != "" {
		version = v
	}
	if c != "" {
		commit = c
	}
	if d != "" {
		date = d
	}
	rootCmd.Version = fmt.Sprintf("%s (commit: %s, date: %s)", version, commit, date)
}

// Execute runs the root CLI command.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.AddCommand(initCmd)
	rootCmd.AddCommand(wrapCmd)
	rootCmd.AddCommand(logsCmd)
	rootCmd.AddCommand(statsCmd)
	rootCmd.AddCommand(serveCmd)
	rootCmd.AddCommand(versionCmd)
}
