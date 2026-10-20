package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/smford/mcp-jail/internal/integrations"
	"github.com/spf13/cobra"
)

var (
	installServer string
	installPath   string
)

var installCmd = &cobra.Command{
	Use:   "install <client>",
	Short: "Automatically configure AI clients (Antigravity CLI/GUI, Claude Desktop, Cursor, Windsurf) to wrap MCP servers with mcp-jail",
	Long: `Patches client configuration files to automatically wrap configured MCP servers with mcp-jail.
Creates an automatic backup of the existing config before making any changes.

Supported clients:
  • antigravity       (Configures both Antigravity / Gemini CLI and GUI)
  • antigravity-cli   (Gemini / Antigravity CLI: ~/.gemini/antigravity-cli/mcp_config.json)
  • antigravity-gui   (Gemini / Antigravity GUI / IDE: ~/.gemini/config/mcp_config.json)
  • gemini            (Alias for antigravity)
  • claude            (Claude Desktop)
  • cursor            (Cursor IDE)
  • windsurf          (Windsurf IDE)
  • workspace         (Current workspace: ./.cursor/mcp.json, ./.vscode/mcp.json, ./mcp.json)`,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) != 1 {
			return fmt.Errorf("missing client name. Supported clients: %s", strings.Join(integrations.SupportedClients, ", "))
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		client := args[0]
		results, err := integrations.Install(client, installServer, installPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[mcp-jail] install error: %v\n", err)
			os.Exit(1)
		}

		for _, res := range results {
			fmt.Printf("Successfully updated configuration at: %s\n", res.ConfigPath)
			fmt.Printf("Backup saved to: %s\n\n", res.BackupPath)

			if len(res.Wrapped) > 0 {
				fmt.Println("Wrapped servers:")
				for _, s := range res.Wrapped {
					fmt.Printf("  ✓ %s\n", s)
				}
			}

			if len(res.Skipped) > 0 {
				fmt.Println("Skipped:")
				for _, s := range res.Skipped {
					fmt.Printf("  - %s\n", s)
				}
			}
			fmt.Println()
		}
	},
}

func init() {
	installCmd.Flags().StringVar(&installServer, "server", "", "Wrap only a specific server name (default: wrap all servers)")
	installCmd.Flags().StringVar(&installPath, "path", "", "Custom path to client configuration file")
}
