package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	version   = "0.4.0"
	commit    = "none"
	date      = "unknown"
	copyright = "Copyright (c) 2026 smford"
	license   = "MIT License"
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

Built as a pure Go standalone binary with no external C dependencies or runtime installations required.

` + copyright + `. Licensed under the ` + license + `.`,
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version, copyright, and license information of mcp-jail",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("mcp-jail %s (commit: %s, date: %s)\n", version, commit, date)
		fmt.Printf("%s\n", copyright)
		fmt.Printf("Licensed under the %s\n", license)
	},
}

var licenseCmd = &cobra.Command{
	Use:   "license",
	Short: "Print copyright and full license terms of mcp-jail",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("mcp-jail %s\n", version)
		fmt.Printf("%s\n\n", copyright)
		fmt.Println(`MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.`)
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
	rootCmd.Version = fmt.Sprintf("%s (commit: %s, date: %s)\n%s\nLicensed under the %s", version, commit, date, copyright, license)
}

// Execute runs the root CLI command.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.Version = fmt.Sprintf("%s (commit: %s, date: %s)\n%s\nLicensed under the %s", version, commit, date, copyright, license)

	rootCmd.AddCommand(initCmd)
	rootCmd.AddCommand(wrapCmd)
	rootCmd.AddCommand(listCmd)
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
	rootCmd.AddCommand(licenseCmd)
}
