package cli

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/smford/mcp-jail/internal/recorder"
	"github.com/spf13/cobra"
)

var (
	logsSessionID   string
	logsBlockedOnly bool
	logsTail        int
	logsDB          string
)

var logsCmd = &cobra.Command{
	Use:   "logs",
	Short: "View flight recorder audit trail of tool calls and policy blocks",
	Long:  "Queries the SQLite flight recorder and prints a human-readable audit trail of tool calls, latency, redactions, and policy blocks.",
	RunE: func(cmd *cobra.Command, args []string) error {
		rec, err := recorder.NewRecorder(logsDB)
		if err != nil {
			return fmt.Errorf("failed to open flight recorder: %w", err)
		}
		defer rec.Close()

		filter := recorder.EventFilter{
			SessionID:   logsSessionID,
			BlockedOnly: logsBlockedOnly,
			Limit:       logsTail,
		}

		events, err := rec.GetEvents(filter)
		if err != nil {
			return fmt.Errorf("failed to query events: %w", err)
		}

		if len(events) == 0 {
			if logsSessionID != "" {
				fmt.Printf("No events recorded for session %s\n", logsSessionID)
			} else {
				fmt.Println("No events recorded in flight recorder.")
			}
			return nil
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "TIMESTAMP\tDIR\tRPC ID\tTOOL/METHOD\tACTION\tLATENCY\tDETAILS")

		for _, ev := range events {
			ts := ev.Timestamp.Format("15:04:05.000")
			dir := "→"
			if ev.Direction == recorder.DirectionServerToHost {
				dir = "←"
			}

			actionStr := formatAction(ev.Action)
			toolOrMethod := ev.ToolName
			if toolOrMethod == "" {
				toolOrMethod = ev.Method
			}
			if toolOrMethod == "" {
				toolOrMethod = "-"
			}

			latencyStr := "-"
			if ev.LatencyMs > 0 {
				latencyStr = fmt.Sprintf("%dms", ev.LatencyMs)
			}

			details := ""
			if ev.RuleTriggered != "" {
				details = fmt.Sprintf("Rule: %s", ev.RuleTriggered)
			} else if ev.Action == recorder.ActionRedacted {
				details = "Secrets scrubbed from output"
			} else if len(ev.PayloadJSON) > 0 {
				// Compact preview
				p := strings.ReplaceAll(ev.PayloadJSON, "\n", " ")
				if len(p) > 60 {
					p = p[:57] + "..."
				}
				details = p
			}

			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
				ts, dir, ev.RPCID, toolOrMethod, actionStr, latencyStr, details)
		}

		return w.Flush()
	},
}

func formatAction(action recorder.Action) string {
	switch action {
	case recorder.ActionBlocked:
		return "\033[1;31mBLOCKED\033[0m"
	case recorder.ActionRedacted:
		return "\033[1;33mREDACTED\033[0m"
	case recorder.ActionAllowed:
		return "\033[1;32mALLOWED\033[0m"
	default:
		return string(action)
	}
}

func init() {
	logsCmd.Flags().StringVar(&logsSessionID, "session", "", "Filter logs by specific session ID")
	logsCmd.Flags().BoolVar(&logsBlockedOnly, "blocked-only", false, "Show only blocked policy violations")
	logsCmd.Flags().IntVar(&logsTail, "tail", 50, "Number of most recent events to display")
	logsCmd.Flags().StringVar(&logsDB, "db", "~/.mcp-jail/flight-recorder.db", "Path to SQLite flight recorder database")
}
