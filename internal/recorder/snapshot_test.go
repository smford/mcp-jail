package recorder

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSnapshotAndRollback(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "mcp-jail-snap-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	dbPath := filepath.Join(tempDir, "test.db")
	rec, err := NewRecorder(dbPath)
	if err != nil {
		t.Fatalf("failed to create recorder: %v", err)
	}
	defer rec.Close()

	sessionID := "test-session-rollback"
	targetFile := filepath.Join(tempDir, "sample.txt")
	originalContent := "line 1: initial version\nline 2: sensitive data\n"

	if err := os.WriteFile(targetFile, []byte(originalContent), 0644); err != nil {
		t.Fatalf("failed to write sample file: %v", err)
	}

	// 1. Take snapshot
	if err := rec.SaveSnapshot(sessionID, targetFile, []byte(originalContent)); err != nil {
		t.Fatalf("failed to save snapshot: %v", err)
	}

	has, err := rec.HasSnapshot(sessionID, targetFile)
	if err != nil || !has {
		t.Fatalf("expected HasSnapshot to return true, got has=%v err=%v", has, err)
	}

	// 2. Modify file on disk
	modifiedContent := "line 1: initial version\nline 2: corrupted by rogue agent\n"
	if err := os.WriteFile(targetFile, []byte(modifiedContent), 0644); err != nil {
		t.Fatalf("failed to modify sample file: %v", err)
	}

	// 3. Test diff generation
	diff := GenerateUnifiedDiff(targetFile, []byte(originalContent), []byte(modifiedContent))
	if !strings.Contains(diff, "-line 2: sensitive data") || !strings.Contains(diff, "+line 2: corrupted by rogue agent") {
		t.Fatalf("unexpected diff output:\n%s", diff)
	}

	// 4. Rollback
	restored, err := rec.RollbackSession(sessionID)
	if err != nil {
		t.Fatalf("rollback failed: %v", err)
	}
	if len(restored) != 1 || restored[0] != targetFile {
		t.Fatalf("unexpected restored files list: %v", restored)
	}

	// 5. Verify restored content matches original
	restoredBytes, err := os.ReadFile(targetFile)
	if err != nil {
		t.Fatalf("failed to read restored file: %v", err)
	}
	if string(restoredBytes) != originalContent {
		t.Fatalf("restored content does not match original: %q != %q", string(restoredBytes), originalContent)
	}
}
