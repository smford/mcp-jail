package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/smford/mcp-jail/internal/integrations"
	"github.com/spf13/cobra"
)

var (
	listJSON bool
	listPath string
)

var listCmd = &cobra.Command{
	Use:     "list [client]",
	Aliases: []string{"servers", "status"},
	Short:   "List installed MCP servers across AI clients and their protection status",
	Long: `Discovers and lists all MCP servers configured across supported AI clients
(Antigravity CLI, Antigravity GUI / IDE, Claude Desktop, Cursor, Windsurf).

Displays whether each server is currently protected by mcp-jail, running unprotected,
or pointing to a remote server URL.

Supported clients for filtering:
  antigravity, antigravity-cli, antigravity-gui, gemini, claude, cursor, windsurf`,
	Run: func(cmd *cobra.Command, args []string) {
		clientFilter := ""
		if len(args) > 0 {
			clientFilter = args[0]
		}

		servers, err := integrations.ListServers(clientFilter, listPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[mcp-jail] list error: %v\n", err)
			os.Exit(1)
		}

		if listJSON {
			out, err := json.MarshalIndent(servers, "", "  ")
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to marshal json: %v\n", err)
				os.Exit(1)
			}
			fmt.Println(string(out))
			return
		}

		if len(servers) == 0 {
			if clientFilter != "" {
				fmt.Printf("No MCP servers found for client %q.\n", clientFilter)
			} else {
				fmt.Println("No configured MCP servers found across known AI clients.")
			}
			return
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
		fmt.Fprintln(w, "CLIENT\tSERVER\tSTATUS\tTARGET")

		var protectedCount, unprotectedCount, remoteCount int
		clientSet := make(map[string]bool)

		for _, s := range servers {
			clientSet[s.Client] = true
			statusDisplay := s.Status
			switch {
			case s.Status == "Protected":
				protectedCount++
				statusDisplay = "✓ Protected"
			case strings.HasPrefix(s.Status, "Unprotected"):
				unprotectedCount++
				statusDisplay = "! " + s.Status
			case s.Status == "Remote URL":
				remoteCount++
				statusDisplay = "• Remote URL"
			}

			targetDisplay := s.Target
			// Truncate overly long targets if necessary for display
			if len(targetDisplay) > 70 {
				targetDisplay = targetDisplay[:67] + "..."
			}

			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", s.Client, s.Name, statusDisplay, targetDisplay)
		}
		w.Flush()

		fmt.Println()
		fmt.Printf("Total: %d server(s) across %d client config(s) (%d protected, %d unprotected, %d remote)\n",
			len(servers), len(clientSet), protectedCount, unprotectedCount, remoteCount)

		if unprotectedCount > 0 {
			fmt.Println("\nTip: Run 'mcp-jail install <client>' to wrap and protect unprotected servers.")
		}
	},
}

func init() {
	listCmd.Flags().BoolVar(&listJSON, "json", false, "Output server list in JSON format")
	listCmd.Flags().StringVar(&listPath, "path", "", "Custom path to a client configuration file")
}
