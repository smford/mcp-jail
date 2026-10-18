package alert

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/smford/mcp-jail/internal/config"
)

func TestDispatcher_Dispatch(t *testing.T) {
	var received Event
	var wg sync.WaitGroup
	wg.Add(1)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer wg.Done()
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("expected Content-Type application/json, got %s", r.Header.Get("Content-Type"))
		}
		_ = json.NewDecoder(r.Body).Decode(&received)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := config.AlertsConfig{
		Enabled:    true,
		WebhookURL: server.URL,
		Events:     []string{"policy_violation"},
	}

	d := NewDispatcher(cfg)

	// Send unsubscribed event - should not be received
	d.Dispatch(Event{
		Type: "unknown_event",
	})

	// Send subscribed event
	d.Dispatch(Event{
		Type:      "policy_violation",
		SessionID: "sess-123",
		Tool:      "execute_command",
		Reason:    "command denied",
	})

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		if received.SessionID != "sess-123" || received.Tool != "execute_command" {
			t.Fatalf("unexpected event received: %+v", received)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for webhook dispatch")
	}
}
