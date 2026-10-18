package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	version = "0.2.0"
	commit  = "none"
	date    = "unknown"
)

var rootCmd = &cobra.Command{
	Use:   "mcp-jail",
	Short: "Lightweight security proxy and flight recorder for Model Context Protocol (MCP) servers",
	Long: `mcp-jail is a standalone security guard and flight recorder for Model Context Protocol (MCP) servers.

It sits transparently between your AI coding agent (Claude Code, Cursor, Antigravity, Claude Desktop)
and local MCP servers to:
  • Prevent accidental damage by blocking dangerous shell commands (rm -rf, git push --force)
  • Enforce strict filesystem boundaries so tools cannot wander into sensitive directories (~/.ssh, ~/.aws, .env)
  • Protect your privacy by automatically redacting API keys and secrets before they enter the AI prompt
  • Stop runaway loops and surprise bills with rate and token budget limiters
  • Provide a complete, queryable flight recorder of every tool call and blocked action

Built as a pure Go standalone binary with no external C dependencies or runtime installations required.`,
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
	rootCmd.AddCommand(diffCmd)
	rootCmd.AddCommand(rollbackCmd)
	rootCmd.AddCommand(learnCmd)
	rootCmd.AddCommand(topCmd)
	rootCmd.AddCommand(proxyCmd)
	rootCmd.AddCommand(installCmd)
	rootCmd.AddCommand(uninstallCmd)
	rootCmd.AddCommand(testPolicyCmd)
	rootCmd.AddCommand(lintPolicyCmd)
	rootCmd.AddCommand(versionCmd)
}
