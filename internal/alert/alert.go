package alert

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/smford/mcp-jail/internal/config"
)

// Event represents an alert dispatched on policy violation or critical security state.
type Event struct {
	Type      string                 `json:"event_type"`
	Timestamp string                 `json:"timestamp"`
	SessionID string                 `json:"session_id,omitempty"`
	Tool      string                 `json:"tool,omitempty"`
	Reason    string                 `json:"reason,omitempty"`
	Details   map[string]interface{} `json:"details,omitempty"`
}

// desktopNotifyFunc defines the signature for delivering desktop popups (mockable in tests).
type desktopNotifyFunc func(title, message string) error

var notifyDesktop desktopNotifyFunc = defaultDesktopNotify

func defaultDesktopNotify(title, message string) error {
	switch runtime.GOOS {
	case "darwin":
		script := fmt.Sprintf("display notification %q with title %q", message, title)
		cmd := exec.Command("osascript", "-e", script)
		return cmd.Run()
	case "linux":
		cmd := exec.Command("notify-send", title, message)
		return cmd.Run()
	default:
		return nil
	}
}

// Dispatcher sends security notifications asynchronously to configured webhooks and desktop environments.
type Dispatcher struct {
	mu         sync.RWMutex
	cfg        config.AlertsConfig
	client     *http.Client
	subscribed map[string]bool
}

// NewDispatcher initializes an alert dispatcher with the given configuration.
func NewDispatcher(cfg config.AlertsConfig) *Dispatcher {
	subMap := make(map[string]bool)
	for _, ev := range cfg.Events {
		subMap[strings.ToLower(strings.TrimSpace(ev))] = true
	}

	return &Dispatcher{
		cfg: cfg,
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
		subscribed: subMap,
	}
}

// IsSubscribed returns true if the dispatcher is enabled and listening for the given event type.
func (d *Dispatcher) IsSubscribed(eventType string) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if !d.cfg.Enabled || (d.cfg.WebhookURL == "" && !d.cfg.Desktop) {
		return false
	}
	if len(d.subscribed) == 0 {
		return true // Listen to all if list empty
	}
	return d.subscribed[strings.ToLower(strings.TrimSpace(eventType))]
}

// FormatWebhookPayload prepares the JSON payload according to the configured webhook format.
func FormatWebhookPayload(format string, evt Event) ([]byte, error) {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "slack":
		toolStr := evt.Tool
		if toolStr == "" {
			toolStr = "(n/a)"
		}
		text := fmt.Sprintf("🚨 *mcp-jail Security Alert*\n*Event*: `%s`\n*Tool*: `%s`\n*Reason*: %s", evt.Type, toolStr, evt.Reason)
		payload := map[string]interface{}{
			"text": text,
		}
		return json.Marshal(payload)

	case "discord":
		toolStr := evt.Tool
		if toolStr == "" {
			toolStr = "(n/a)"
		}
		content := fmt.Sprintf("🚨 **mcp-jail Security Alert**\n**Event**: `%s`\n**Tool**: `%s`\n**Reason**: %s", evt.Type, toolStr, evt.Reason)
		payload := map[string]interface{}{
			"content": content,
		}
		return json.Marshal(payload)

	default: // "generic"
		return json.Marshal(evt)
	}
}

// Dispatch sends the event asynchronously via webhook and/or native desktop alert.
func (d *Dispatcher) Dispatch(evt Event) {
	if !d.IsSubscribed(evt.Type) {
		return
	}

	if evt.Timestamp == "" {
		evt.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}

	d.mu.RLock()
	webhookURL := d.cfg.WebhookURL
	webhookFormat := d.cfg.WebhookFormat
	desktop := d.cfg.Desktop
	d.mu.RUnlock()

	// Dispatch desktop popup notification
	if desktop {
		go func(e Event) {
			toolMsg := e.Tool
			if toolMsg == "" {
				toolMsg = e.Type
			}
			msg := fmt.Sprintf("Security alert on %s: %s", toolMsg, e.Reason)
			_ = notifyDesktop("mcp-jail Alert", msg)
		}(evt)
	}

	// Dispatch HTTP webhook
	if webhookURL != "" {
		go func(payload Event, url, format string) {
			data, err := FormatWebhookPayload(format, payload)
			if err != nil {
				return
			}

			req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(data))
			if err != nil {
				return
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("User-Agent", "mcp-jail/security-alerts")

			resp, err := d.client.Do(req)
			if err == nil && resp != nil {
				_ = resp.Body.Close()
			}
		}(evt, webhookURL, webhookFormat)
	}
}
