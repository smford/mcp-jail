package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "mcp-jail",
	Short: "Zero-CGO local firewall and flight-recorder proxy for Model Context Protocol (MCP) servers",
	Long: `mcp-jail sits transparently between an AI host agent (Claude Code, Cursor, Antigravity)
and local MCP servers to enforce filesystem boundaries, guard against dangerous shell commands,
prevent runaway agent rate/budget loops, and redact outbound credentials.`,
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
}
