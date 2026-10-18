package cli

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/smford/mcp-jail/internal/recorder"
	"github.com/spf13/cobra"
)

var topCmd = &cobra.Command{
	Use:   "top",
	Short: "Live terminal activity monitor for MCP sessions and security events",
	Long: `Display a continuously updating dashboard of active MCP sessions,
real-time tool calls, policy violations, and latency metrics.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		dbPath, _ := cmd.Flags().GetString("db")
		once, _ := cmd.Flags().GetBool("once")
		intervalSec, _ := cmd.Flags().GetInt("interval")
		if intervalSec <= 0 {
			intervalSec = 1
		}

		rec, err := recorder.NewRecorder(dbPath)
		if err != nil {
			return fmt.Errorf("failed to open flight recorder: %w", err)
		}
		defer rec.Close()

		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

		render := func() error {
			stats, err := rec.GetStats("")
			if err != nil {
				return err
			}

			sessions, err := rec.ListSessions(5)
			if err != nil {
				return err
			}

			events, err := rec.GetEvents(recorder.EventFilter{Limit: 12})
			if err != nil {
				return err
			}

			// Clear terminal screen and move cursor to home
			fmt.Print("\033[H\033[2J")

			fmt.Printf("\033[1;36m=== mcp-jail Top: Live MCP Activity Monitor ===\033[0m   [%s]\n", time.Now().Format("15:04:05"))
			fmt.Printf("Total Sessions: \033[1m%d\033[0m | Total Calls: \033[1;32m%d\033[0m | Blocked: \033[1;31m%d\033[0m | Redacted: \033[1;33m%d\033[0m | Tokens: \033[1;35m%d\033[0m\n",
				stats.TotalSessions, stats.TotalCalls, stats.BlockedCalls, stats.RedactedSecrets, stats.EstTokens)
			fmt.Println("──────────────────────────────────────────────────────────────────────────────")

			fmt.Println("\033[1mRECENT SESSIONS:\033[0m")
			if len(sessions) == 0 {
				fmt.Println("  (no recorded sessions yet)")
			} else {
				fmt.Printf("  %-16s %-10s %-8s %-8s %-10s %s\n", "SESSION ID", "STARTED", "CALLS", "BLOCKED", "TOKENS", "COMMAND")
				for _, s := range sessions {
					shortID := s.ID
					if len(shortID) > 14 {
						shortID = shortID[:14] + ".."
					}
					shortCmd := s.Command
					if len(shortCmd) > 30 {
						shortCmd = shortCmd[:27] + "..."
					}
					fmt.Printf("  %-16s %-10s %-8d %-8d %-10d %s\n",
						shortID, s.StartedAt.Format("15:04:05"), s.TotalCalls, s.BlockedCalls, s.EstTokens, shortCmd)
				}
			}

			fmt.Println("──────────────────────────────────────────────────────────────────────────────")
			fmt.Println("\033[1mLIVE EVENT STREAM:\033[0m")
			if len(events) == 0 {
				fmt.Println("  (no recorded events yet)")
			} else {
				fmt.Printf("  %-10s %-12s %-14s %-10s %-10s\n", "TIME", "DIRECTION", "TOOL/METHOD", "ACTION", "LATENCY")
				for _, ev := range events {
					actionColor := "\033[32m"
					if ev.Action == recorder.ActionBlocked {
						actionColor = "\033[1;31m"
					} else if ev.Action == recorder.ActionRedacted {
						actionColor = "\033[1;33m"
					}

					name := ev.ToolName
					if name == "" {
						name = ev.Method
					}
					if len(name) > 14 {
						name = name[:12] + ".."
					}

					latStr := "-"
					if ev.LatencyMs > 0 {
						latStr = fmt.Sprintf("%dms", ev.LatencyMs)
					}

					fmt.Printf("  %-10s %-12s %-14s %s%-10s\033[0m %-10s\n",
						ev.Timestamp.Format("15:04:05"),
						ev.Direction,
						name,
						actionColor,
						ev.Action,
						latStr,
					)
				}
			}
			fmt.Println("──────────────────────────────────────────────────────────────────────────────")
			if !once {
				fmt.Printf("Refreshing every %ds. Press Ctrl+C to exit.\n", intervalSec)
			}
			return nil
		}

		if err := render(); err != nil {
			return err
		}
		if once {
			return nil
		}

		ticker := time.NewTicker(time.Duration(intervalSec) * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-sigChan:
				fmt.Println("\nExiting monitor.")
				return nil
			case <-ticker.C:
				if err := render(); err != nil {
					return err
				}
			}
		}
	},
}

func init() {
	topCmd.Flags().String("db", "", "Path to SQLite flight recorder database")
	topCmd.Flags().IntP("interval", "i", 1, "Refresh interval in seconds")
	topCmd.Flags().Bool("once", false, "Render a single snapshot and exit immediately")
}
