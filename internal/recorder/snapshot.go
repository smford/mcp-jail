package recorder

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// FileSnapshot records the state of a file before modification.
type FileSnapshot struct {
	ID        int64     `json:"id"`
	SessionID string    `json:"session_id"`
	FilePath  string    `json:"file_path"`
	Content   []byte    `json:"content"`
	CreatedAt time.Time `json:"created_at"`
}

// HasSnapshot checks if a pre-modification snapshot already exists for this file in the session.
func (r *Recorder) HasSnapshot(sessionID, filePath string) (bool, error) {
	var count int
	err := r.db.QueryRow("SELECT COUNT(*) FROM file_snapshots WHERE session_id = ? AND file_path = ?",
		sessionID, filePath).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// SaveSnapshot saves a file snapshot for a session.
func (r *Recorder) SaveSnapshot(sessionID, filePath string, content []byte) error {
	_, err := r.db.Exec(`
		INSERT INTO file_snapshots (session_id, file_path, snapshot_content, created_at)
		VALUES (?, ?, ?, ?)
	`, sessionID, filePath, content, time.Now())
	return err
}

// GetSnapshots retrieves all file snapshots captured during a session.
func (r *Recorder) GetSnapshots(sessionID string) ([]FileSnapshot, error) {
	rows, err := r.db.Query(`
		SELECT id, session_id, file_path, snapshot_content, created_at
		FROM file_snapshots
		WHERE session_id = ?
		ORDER BY id ASC
	`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var snapshots []FileSnapshot
	for rows.Next() {
		var s FileSnapshot
		if err := rows.Scan(&s.ID, &s.SessionID, &s.FilePath, &s.Content, &s.CreatedAt); err != nil {
			return nil, err
		}
		snapshots = append(snapshots, s)
	}
	return snapshots, nil
}

// RollbackSession restores all files modified in a session to their original snapshot states.
func (r *Recorder) RollbackSession(sessionID string) ([]string, error) {
	snapshots, err := r.GetSnapshots(sessionID)
	if err != nil {
		return nil, fmt.Errorf("failed to query snapshots: %w", err)
	}
	if len(snapshots) == 0 {
		return nil, fmt.Errorf("no snapshots found for session %s", sessionID)
	}

	var restored []string
	for _, snap := range snapshots {
		// Ensure parent directory exists
		if err := os.MkdirAll(filepath.Dir(snap.FilePath), 0755); err != nil {
			return restored, fmt.Errorf("failed to create dir for %s: %w", snap.FilePath, err)
		}
		if err := os.WriteFile(snap.FilePath, snap.Content, 0644); err != nil {
			return restored, fmt.Errorf("failed to restore file %s: %w", snap.FilePath, err)
		}
		restored = append(restored, snap.FilePath)
	}
	return restored, nil
}

// GenerateUnifiedDiff generates a simple unified diff between old and new byte slices.
func GenerateUnifiedDiff(path string, original, current []byte) string {
	if bytes.Equal(original, current) {
		return ""
	}

	var buf strings.Builder
	buf.WriteString(fmt.Sprintf("--- a/%s\n", path))
	buf.WriteString(fmt.Sprintf("+++ b/%s\n", path))

	oldLines := strings.Split(string(original), "\n")
	newLines := strings.Split(string(current), "\n")

	// Simple line-by-line diff
	i, j := 0, 0
	for i < len(oldLines) && j < len(newLines) {
		if oldLines[i] == newLines[j] {
			buf.WriteString(" " + oldLines[i] + "\n")
			i++
			j++
		} else {
			buf.WriteString("-" + oldLines[i] + "\n")
			buf.WriteString("+" + newLines[j] + "\n")
			i++
			j++
		}
	}
	for ; i < len(oldLines); i++ {
		buf.WriteString("-" + oldLines[i] + "\n")
	}
	for ; j < len(newLines); j++ {
		buf.WriteString("+" + newLines[j] + "\n")
	}

	return buf.String()
}
