package alert

import (
	"bytes"
	"encoding/json"
	"net/http"
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

// Dispatcher sends security notifications asynchronously to configured webhooks.
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

	if !d.cfg.Enabled || d.cfg.WebhookURL == "" {
		return false
	}
	if len(d.subscribed) == 0 {
		return true // Listen to all if list empty
	}
	return d.subscribed[strings.ToLower(strings.TrimSpace(eventType))]
}

// Dispatch sends the event asynchronously in a goroutine.
func (d *Dispatcher) Dispatch(evt Event) {
	if !d.IsSubscribed(evt.Type) {
		return
	}

	if evt.Timestamp == "" {
		evt.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}

	go func(payload Event, webhookURL string) {
		data, err := json.Marshal(payload)
		if err != nil {
			return
		}

		req, err := http.NewRequest(http.MethodPost, webhookURL, bytes.NewReader(data))
		if err != nil {
			return
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "mcp-jail/security-alerts")

		resp, err := d.client.Do(req)
		if err == nil && resp != nil {
			_ = resp.Body.Close()
		}
	}(evt, d.cfg.WebhookURL)
}
