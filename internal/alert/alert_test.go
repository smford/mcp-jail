package alert

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/smford/mcp-jail/internal/config"
)

func TestDispatcher_GenericWebhook(t *testing.T) {
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
		Enabled:       true,
		WebhookURL:    server.URL,
		WebhookFormat: "generic",
		Events:        []string{"policy_violation"},
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
		t.Fatal("timed out waiting for generic webhook dispatch")
	}
}

func TestDispatcher_SlackWebhook(t *testing.T) {
	var bodyMap map[string]interface{}
	var wg sync.WaitGroup
	wg.Add(1)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer wg.Done()
		_ = json.NewDecoder(r.Body).Decode(&bodyMap)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := config.AlertsConfig{
		Enabled:       true,
		WebhookURL:    server.URL,
		WebhookFormat: "slack",
	}

	d := NewDispatcher(cfg)
	d.Dispatch(Event{
		Type:   "policy_violation",
		Tool:   "format_disk",
		Reason: "destructive command blocked",
	})

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		text, ok := bodyMap["text"].(string)
		if !ok || !strings.Contains(text, "format_disk") || !strings.Contains(text, "destructive command blocked") {
			t.Fatalf("unexpected slack payload: %+v", bodyMap)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for slack webhook dispatch")
	}
}

func TestDispatcher_DiscordWebhook(t *testing.T) {
	var bodyMap map[string]interface{}
	var wg sync.WaitGroup
	wg.Add(1)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer wg.Done()
		_ = json.NewDecoder(r.Body).Decode(&bodyMap)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := config.AlertsConfig{
		Enabled:       true,
		WebhookURL:    server.URL,
		WebhookFormat: "discord",
	}

	d := NewDispatcher(cfg)
	d.Dispatch(Event{
		Type:   "policy_violation",
		Tool:   "git_push",
		Reason: "force push denied",
	})

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		content, ok := bodyMap["content"].(string)
		if !ok || !strings.Contains(content, "git_push") || !strings.Contains(content, "force push denied") {
			t.Fatalf("unexpected discord payload: %+v", bodyMap)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for discord webhook dispatch")
	}
}

func TestDispatcher_DesktopAlert(t *testing.T) {
	var notifiedTitle, notifiedMsg string
	var wg sync.WaitGroup
	wg.Add(1)

	origNotifier := notifyDesktop
	defer func() { notifyDesktop = origNotifier }()

	notifyDesktop = func(title, message string) error {
		notifiedTitle = title
		notifiedMsg = message
		wg.Done()
		return nil
	}

	cfg := config.AlertsConfig{
		Enabled: true,
		Desktop: true,
	}

	d := NewDispatcher(cfg)
	d.Dispatch(Event{
		Type:   "policy_violation",
		Tool:   "execute_sql",
		Reason: "DROP DATABASE statement blocked",
	})

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		if !strings.Contains(notifiedTitle, "mcp-jail") {
			t.Errorf("unexpected desktop title: %s", notifiedTitle)
		}
		if !strings.Contains(notifiedMsg, "execute_sql") || !strings.Contains(notifiedMsg, "DROP DATABASE") {
			t.Errorf("unexpected desktop msg: %s", notifiedMsg)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for desktop notification")
	}
}
