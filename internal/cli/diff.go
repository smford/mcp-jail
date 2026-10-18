package cli

import (
	"fmt"
	"os"

	"github.com/smford/mcp-jail/internal/recorder"
	"github.com/spf13/cobra"
)

var diffCmd = &cobra.Command{
	Use:   "diff [session-id]",
	Short: "Show unified diff of file changes made during an MCP session",
	Long: `Inspect all file changes recorded during an AI coding agent session.
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

		snapshots, err := rec.GetSnapshots(sessionID)
		if err != nil {
			return fmt.Errorf("failed to query snapshots: %w", err)
		}

		if len(snapshots) == 0 {
			fmt.Printf("No file snapshots recorded for session %s.\n", sessionID)
			return nil
		}

		fmt.Printf("File diff for session %s (%d files tracked):\n\n", sessionID, len(snapshots))

		totalDiffs := 0
		for _, snap := range snapshots {
			current, err := os.ReadFile(snap.FilePath)
			if err != nil {
				fmt.Printf("⚠️ File removed or unreadable: %s\n", snap.FilePath)
				continue
			}

			diff := recorder.GenerateUnifiedDiff(snap.FilePath, snap.Content, current)
			if diff != "" {
				totalDiffs++
				fmt.Print(diff)
				fmt.Println()
			}
		}

		if totalDiffs == 0 {
			fmt.Println("No modifications detected. Files on disk match their pre-session snapshot states.")
		}

		return nil
	},
}

func init() {
	diffCmd.Flags().String("db", "", "Path to SQLite flight recorder database")
}
