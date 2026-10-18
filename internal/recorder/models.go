package recorder

import (
	"time"
)

// Direction represents message direction.
type Direction string

const (
	DirectionHostToServer Direction = "host_to_server"
	DirectionServerToHost Direction = "server_to_host"
)

// Action represents the outcome of an event.
type Action string

const (
	ActionAllowed  Action = "allowed"
	ActionBlocked  Action = "blocked"
	ActionRedacted Action = "redacted"
)

// Session represents a recorded MCP session.
type Session struct {
	ID              string     `json:"id"`
	StartedAt       time.Time  `json:"started_at"`
	EndedAt         *time.Time `json:"ended_at,omitempty"`
	Command         string     `json:"command"`
	Cwd             string     `json:"cwd"`
	TotalCalls      int        `json:"total_calls"`
	BlockedCalls    int        `json:"blocked_calls"`
	RedactedSecrets int        `json:"redacted_secrets"`
	EstTokens       int64      `json:"est_tokens"`
}

// Event represents an individual intercepted JSON-RPC message or policy event.
type Event struct {
	ID            int64     `json:"id"`
	SessionID     string    `json:"session_id"`
	Timestamp     time.Time `json:"timestamp"`
	Direction     Direction `json:"direction"`
	RPCID         string    `json:"rpc_id"`
	Method        string    `json:"method"`
	ToolName      string    `json:"tool_name"`
	Action        Action    `json:"action"`
	RuleTriggered string    `json:"rule_triggered"`
	LatencyMs     int64     `json:"latency_ms"`
	PayloadJSON   string    `json:"payload_json"`
}

// EventFilter specifies filters for querying events.
type EventFilter struct {
	SessionID   string
	BlockedOnly bool
	Limit       int
	Offset      int
}

// ToolCount holds aggregation counts for tools.
type ToolCount struct {
	ToolName string `json:"tool_name"`
	Count    int    `json:"count"`
}

// StatsSummary holds aggregated metrics for sessions.
type StatsSummary struct {
	SessionID       string      `json:"session_id,omitempty"`
	TotalSessions   int         `json:"total_sessions"`
	TotalCalls      int         `json:"total_calls"`
	BlockedCalls    int         `json:"blocked_calls"`
	RedactedSecrets int         `json:"redacted_secrets"`
	EstTokens       int64       `json:"est_tokens"`
	TopTools        []ToolCount `json:"top_tools"`
}
