package cli

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/smford/mcp-jail/internal/recorder"
)

var rollbackCmd = &cobra.Command{
	Use:   "rollback [session-id]",
	Short: "Revert all file modifications made during an MCP session to pre-session snapshots",
	Long: `Rollback any files modified during an AI agent session to their pre-session snapshot state.
If no session ID is specified, the most recent session is used.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		dbPath, _ := cmd.Flags().GetString("db")
		rec, err := recorder.NewRecorder(dbPath)
		if err != nil {
			return fmt.Errorf("failed to open flight recorder: %w", err)
		}
		defer rec.Close()

		sessionID := ""
		if len(args) > 0 {
			sessionID = args[0]
		} else {
			sessions, err := rec.ListSessions(1)
			if err != nil || len(sessions) == 0 {
				return fmt.Errorf("no sessions found in flight recorder")
			}
			sessionID = sessions[0].ID
		}

		restored, err := rec.RollbackSession(sessionID)
		if err != nil {
			return fmt.Errorf("rollback failed: %w", err)
		}

		fmt.Printf("✅ Successfully rolled back session %s (%d files restored):\n", sessionID, len(restored))
		for _, f := range restored {
			fmt.Printf("  • %s\n", f)
		}

		return nil
	},
}

func init() {
	rollbackCmd.Flags().String("db", "", "Path to SQLite flight recorder database")
}
