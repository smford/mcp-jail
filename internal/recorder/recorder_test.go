package recorder

import (
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestRecorderConcurrentLogging(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test-flight-recorder.db")

	rec, err := NewRecorder(dbPath)
	if err != nil {
		t.Fatalf("failed to create recorder: %v", err)
	}

	sessionID := "test-sess-001"
	err = rec.StartSession(&Session{
		ID:        sessionID,
		StartedAt: time.Now(),
		Command:   "mock-mcp-server",
		Cwd:       "/test/cwd",
	})
	if err != nil {
		t.Fatalf("failed to start session: %v", err)
	}

	// Concurrent logging of 100 events
	var wg sync.WaitGroup
	eventCount := 100
	for i := 0; i < eventCount; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			action := ActionAllowed
			rule := ""
			if idx%5 == 0 {
				action = ActionBlocked
				rule = "filesystem_boundary"
			}
			rec.RecordEvent(&Event{
				SessionID:     sessionID,
				Timestamp:     time.Now(),
				Direction:     DirectionHostToServer,
				RPCID:         fmt.Sprintf("req-%d", idx),
				Method:        "tools/call",
				ToolName:      "read_file",
				Action:        action,
				RuleTriggered: rule,
				LatencyMs:     int64(idx * 2),
				PayloadJSON:   `{"path": "safe.txt"}`,
			})
		}(i)
	}

	wg.Wait()

	// Update session counters and close to flush
	rec.EndSession(sessionID, eventCount, 20, 5, 1250)
	if err := rec.Close(); err != nil {
		t.Fatalf("failed to close recorder: %v", err)
	}

	// Reopen to verify query
	rec2, err := NewRecorder(dbPath)
	if err != nil {
		t.Fatalf("failed to reopen recorder: %v", err)
	}
	defer rec2.Close()

	sess, err := rec2.GetSession(sessionID)
	if err != nil {
		t.Fatalf("failed to get session: %v", err)
	}
	if sess.TotalCalls != eventCount {
		t.Errorf("expected %d total calls, got %d", eventCount, sess.TotalCalls)
	}
	if sess.BlockedCalls != 20 {
		t.Errorf("expected 20 blocked calls, got %d", sess.BlockedCalls)
	}

	events, err := rec2.GetEvents(EventFilter{SessionID: sessionID})
	if err != nil {
		t.Fatalf("failed to get events: %v", err)
	}
	if len(events) != eventCount {
		t.Errorf("expected %d events, got %d", eventCount, len(events))
	}

	// Test blocked only filter
	blockedEvents, err := rec2.GetEvents(EventFilter{
		SessionID:   sessionID,
		BlockedOnly: true,
	})
	if err != nil {
		t.Fatalf("failed to get blocked events: %v", err)
	}
	if len(blockedEvents) != 20 {
		t.Errorf("expected 20 blocked events, got %d", len(blockedEvents))
	}

	// Test stats summary
	stats, err := rec2.GetStats(sessionID)
	if err != nil {
		t.Fatalf("failed to get stats: %v", err)
	}
	if stats.BlockedCalls != 20 {
		t.Errorf("expected stats blocked calls 20, got %d", stats.BlockedCalls)
	}
	if len(stats.TopTools) == 0 || stats.TopTools[0].ToolName != "read_file" {
		t.Errorf("expected top tool read_file, got %+v", stats.TopTools)
	}

	// Test AfterID filter for streaming
	if len(events) >= 10 {
		midID := events[9].ID
		afterEvents, err := rec2.GetEvents(EventFilter{
			SessionID: sessionID,
			AfterID:   midID,
		})
		if err != nil {
			t.Fatalf("failed to get events after ID: %v", err)
		}
		expectedAfter := len(events) - 10
		if len(afterEvents) != expectedAfter {
			t.Errorf("expected %d events after ID %d, got %d", expectedAfter, midID, len(afterEvents))
		}
	}
}
