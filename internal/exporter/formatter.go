package exporter

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/smford/mcp-jail/internal/recorder"
)

// Format identifies the structured logging serialization format.
type Format string

const (
	TypeJSON   Format = "json"
	TypeCEF    Format = "cef"
	TypeLogfmt Format = "logfmt"
)

// SupportedFormats lists all valid structured log format identifiers.
var SupportedFormats = []string{
	string(TypeJSON),
	string(TypeCEF),
	string(TypeLogfmt),
}

// FormatCEF formats an event according to the ArcSight / Splunk Common Event Format (CEF:0) standard.
func FormatCEF(ev *recorder.Event, appVersion string) string {
	if appVersion == "" {
		appVersion = "0.6.0"
	}
	vendor := "smford"
	product := "mcp-jail"

	var classID string
	var name string
	var severity int

	switch ev.Action {
	case recorder.ActionBlocked:
		classID = "POLICY_VIOLATION"
		name = "Tool execution blocked by security policy"
		severity = 7
	case recorder.ActionRedacted:
		classID = "SECRET_REDACTED"
		name = "Outbound secret credential redacted"
		severity = 5
	default:
		classID = "TOOL_INVOCATION"
		name = "Tool invocation permitted"
		severity = 1
	}

	escapeHeader := func(s string) string {
		s = strings.ReplaceAll(s, `\`, `\\`)
		s = strings.ReplaceAll(s, `|`, `\|`)
		return s
	}

	escapeExtension := func(s string) string {
		s = strings.ReplaceAll(s, `\`, `\\`)
		s = strings.ReplaceAll(s, `=`, `\=`)
		s = strings.ReplaceAll(s, "\n", `\n`)
		s = strings.ReplaceAll(s, "\r", "")
		return s
	}

	ext := make([]string, 0, 10)
	ext = append(ext, fmt.Sprintf("act=%s", escapeExtension(string(ev.Action))))
	if ev.ToolName != "" {
		ext = append(ext, fmt.Sprintf("tool=%s", escapeExtension(ev.ToolName)))
	}
	if ev.Method != "" {
		ext = append(ext, fmt.Sprintf("method=%s", escapeExtension(ev.Method)))
	}
	if ev.RuleTriggered != "" {
		ext = append(ext, fmt.Sprintf("reason=%s", escapeExtension(ev.RuleTriggered)))
	}
	if ev.SessionID != "" {
		ext = append(ext, fmt.Sprintf("cs1=%s cs1Label=SessionID", escapeExtension(ev.SessionID)))
	}
	if ev.LatencyMs > 0 {
		ext = append(ext, fmt.Sprintf("cn1=%d cn1Label=LatencyMs", ev.LatencyMs))
	}
	if ev.RPCID != "" {
		ext = append(ext, fmt.Sprintf("cs2=%s cs2Label=RPCID", escapeExtension(ev.RPCID)))
	}
	ext = append(ext, fmt.Sprintf("rt=%d", ev.Timestamp.UnixMilli()))

	return fmt.Sprintf("CEF:0|%s|%s|%s|%s|%s|%d|%s",
		escapeHeader(vendor),
		escapeHeader(product),
		escapeHeader(appVersion),
		escapeHeader(classID),
		escapeHeader(name),
		severity,
		strings.Join(ext, " "),
	)
}

// FormatLogfmt formats an event as human-readable and machine-parseable key=value pairs.
func FormatLogfmt(ev *recorder.Event) string {
	quoteVal := func(s string) string {
		if s == "" {
			return `""`
		}
		if strings.ContainsAny(s, " =\"\n\r\t") {
			escaped := strings.ReplaceAll(s, `"`, `\"`)
			escaped = strings.ReplaceAll(escaped, "\n", " ")
			escaped = strings.ReplaceAll(escaped, "\r", "")
			return `"` + escaped + `"`
		}
		return s
	}

	level := "info"
	if ev.Action == recorder.ActionBlocked {
		level = "warn"
	} else if ev.Action == recorder.ActionRedacted {
		level = "warn"
	}

	parts := make([]string, 0, 10)
	parts = append(parts, fmt.Sprintf("ts=%s", ev.Timestamp.UTC().Format(time.RFC3339)))
	parts = append(parts, fmt.Sprintf("level=%s", level))
	parts = append(parts, fmt.Sprintf("action=%s", string(ev.Action)))

	if ev.SessionID != "" {
		parts = append(parts, fmt.Sprintf("session_id=%s", quoteVal(ev.SessionID)))
	}
	if ev.ToolName != "" {
		parts = append(parts, fmt.Sprintf("tool=%s", quoteVal(ev.ToolName)))
	}
	if ev.Method != "" {
		parts = append(parts, fmt.Sprintf("method=%s", quoteVal(ev.Method)))
	}
	if ev.RuleTriggered != "" {
		parts = append(parts, fmt.Sprintf("rule=%s", quoteVal(ev.RuleTriggered)))
	}
	if ev.LatencyMs > 0 {
		parts = append(parts, fmt.Sprintf("latency_ms=%d", ev.LatencyMs))
	}
	if ev.RPCID != "" {
		parts = append(parts, fmt.Sprintf("rpc_id=%s", quoteVal(ev.RPCID)))
	}
	if ev.Direction != "" {
		parts = append(parts, fmt.Sprintf("direction=%s", quoteVal(string(ev.Direction))))
	}

	return strings.Join(parts, " ")
}

// FormatJSON formats an event as compact single-line JSON.
func FormatJSON(ev *recorder.Event) ([]byte, error) {
	return json.Marshal(ev)
}

// FormatEvent formats an event into bytes according to format ("json", "cef", "logfmt").
func FormatEvent(format string, ev *recorder.Event, appVersion string) ([]byte, error) {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case string(TypeCEF):
		return []byte(FormatCEF(ev, appVersion)), nil
	case string(TypeLogfmt):
		return []byte(FormatLogfmt(ev)), nil
	default: // "json"
		return FormatJSON(ev)
	}
}
