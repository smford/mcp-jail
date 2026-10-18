package cli

import (
	"fmt"

	"github.com/smford/mcp-jail/internal/recorder"
	"github.com/spf13/cobra"
)

var (
	statsSessionID string
	statsDB        string
)

var statsCmd = &cobra.Command{
	Use:   "stats",
	Short: "Print session metrics, policy violations, and token estimates",
	Long:  "Prints session summaries: total tool calls, blocked calls, redacted secrets count, estimated token usage, and top tools invoked.",
	RunE: func(cmd *cobra.Command, args []string) error {
		rec, err := recorder.NewRecorder(statsDB)
		if err != nil {
			return fmt.Errorf("failed to open flight recorder: %w", err)
		}
		defer rec.Close()

		summary, err := rec.GetStats(statsSessionID)
		if err != nil {
			return fmt.Errorf("failed to retrieve stats: %w", err)
		}

		fmt.Println("====================================================")
		if statsSessionID != "" {
			fmt.Printf("          MCP-JAIL STATS FOR SESSION\n")
			fmt.Printf("          %s\n", statsSessionID)
		} else {
			fmt.Printf("            MCP-JAIL FLIGHT RECORDER STATS\n")
		}
		fmt.Println("====================================================")

		if statsSessionID == "" {
			fmt.Printf("Total Sessions Monitored:   %d\n", summary.TotalSessions)
		}
		fmt.Printf("Total Tool Calls:           %d\n", summary.TotalCalls)
		fmt.Printf("Blocked Violations:         %d\n", summary.BlockedCalls)
		fmt.Printf("Redacted Credentials:       %d\n", summary.RedactedSecrets)
		fmt.Printf("Estimated Token Usage:      %d (~%d KB)\n", summary.EstTokens, summary.EstTokens*4/1024)

		if len(summary.TopTools) > 0 {
			fmt.Println("----------------------------------------------------")
			fmt.Println("TOP TOOLS INVOKED:")
			for i, tt := range summary.TopTools {
				fmt.Printf("  %2d. %-24s (%d calls)\n", i+1, tt.ToolName, tt.Count)
			}
		}
		fmt.Println("====================================================")

		return nil
	},
}

func init() {
	statsCmd.Flags().StringVar(&statsSessionID, "session", "", "Filter stats by session ID")
	statsCmd.Flags().StringVar(&statsDB, "db", "~/.mcp-jail/flight-recorder.db", "Path to SQLite flight recorder database")
}
