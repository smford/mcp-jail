package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/smford/mcp-jail/internal/integrations"
	"github.com/spf13/cobra"
)

var (
	uninstallServer string
	uninstallPath   string
)

var uninstallCmd = &cobra.Command{
	Use:   "uninstall <client>",
	Short: "Unwrap and restore original MCP server configurations for AI clients",
	Long: `Restores original MCP server commands by removing the mcp-jail wrapper from client configuration files.

Supported clients:
  • claude    (Claude Desktop)
  • cursor    (Cursor IDE)
  • windsurf  (Windsurf IDE)`,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) != 1 {
			return fmt.Errorf("missing client name. Supported clients: %s", strings.Join(integrations.SupportedClients, ", "))
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		client := args[0]
		res, err := integrations.Uninstall(client, uninstallServer, uninstallPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[mcp-jail] uninstall error: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("Successfully restored %s configuration at: %s\n\n", client, res.ConfigPath)

		if len(res.Unwrapped) > 0 {
			fmt.Println("Restored servers:")
			for _, s := range res.Unwrapped {
				fmt.Printf("  ✓ %s\n", s)
			}
		}

		if len(res.Skipped) > 0 {
			fmt.Println("\nSkipped (not wrapped by mcp-jail):")
			for _, s := range res.Skipped {
				fmt.Printf("  - %s\n", s)
			}
		}
	},
}

func init() {
	uninstallCmd.Flags().StringVar(&uninstallServer, "server", "", "Unwrap only a specific server name (default: unwrap all servers)")
	uninstallCmd.Flags().StringVar(&uninstallPath, "path", "", "Custom path to client configuration file")
}
