package cli

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/smford/mcp-jail/internal/recorder"
	"github.com/spf13/cobra"
)

var (
	replayDB     string
	replayList   bool
	replayTiming bool
)

var replayCmd = &cobra.Command{
	Use:   "replay [session-id]",
	Short: "Deterministically replay recorded MCP sessions for testing and simulation",
	Long: `Starts a mock MCP server that deterministically replays recorded JSON-RPC responses
from a previous session stored in the SQLite flight recorder.

Can be connected to any MCP client (Claude Desktop, Cursor, Antigravity) to re-simulate
previous executions without re-running child processes, touching real APIs, or consuming tokens.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		out := cmd.OutOrStdout()
		errOut := cmd.ErrOrStderr()

		rec, err := recorder.NewRecorder(replayDB)
		if err != nil {
			return fmt.Errorf("failed to open flight recorder: %w", err)
		}
		defer rec.Close()

		if replayList || len(args) == 0 {
			sessions, err := rec.ListSessions(50)
			if err != nil {
				return fmt.Errorf("failed to list sessions: %w", err)
			}
			if len(sessions) == 0 {
				fmt.Fprintln(out, "No recorded sessions found in flight recorder.")
				return nil
			}

			w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "SESSION ID\tSTARTED\tCALLS\tBLOCKED\tCOMMAND")
			for _, s := range sessions {
				started := s.StartedAt.Format("2006-01-02 15:04:05")
				cmdStr := s.Command
				if len(cmdStr) > 40 {
					cmdStr = cmdStr[:37] + "..."
				}
				fmt.Fprintf(w, "%s\t%s\t%d\t%d\t%s\n", s.ID, started, s.TotalCalls, s.BlockedCalls, cmdStr)
			}
			w.Flush()
			if len(args) == 0 && !replayList {
				fmt.Fprintln(errOut, "\nRun 'mcp-jail replay <session-id>' to start replay mock server.")
			}
			return nil
		}

		sessionID := strings.TrimSpace(args[0])
		return RunReplay(cmd.InOrStdin(), out, errOut, rec, sessionID, replayTiming)
	},
}

// ReplayIndex organizes recorded session events for fast response lookup.
type ReplayIndex struct {
	InitializeResp  []byte
	ToolsListResp   []byte
	ResourcesResp   []byte
	PromptsResp     []byte
	ToolResponses   map[string][]*recorder.Event
	ToolIndices     map[string]int
	MethodResponses map[string][]*recorder.Event
	MethodIndices   map[string]int
}

// BuildReplayIndex processes events for a session into a queryable replay index.
func BuildReplayIndex(events []*recorder.Event) *ReplayIndex {
	idx := &ReplayIndex{
		ToolResponses:   make(map[string][]*recorder.Event),
		ToolIndices:     make(map[string]int),
		MethodResponses: make(map[string][]*recorder.Event),
		MethodIndices:   make(map[string]int),
	}

	for _, ev := range events {
		if ev.Direction != recorder.DirectionServerToHost || ev.PayloadJSON == "" {
			continue
		}

		payload := []byte(ev.PayloadJSON)

		// Capture standard discovery endpoints
		if ev.Method == "initialize" {
			if len(idx.InitializeResp) == 0 {
				idx.InitializeResp = payload
			}
		} else if ev.Method == "tools/list" {
			if len(idx.ToolsListResp) == 0 {
				idx.ToolsListResp = payload
			}
		} else if ev.Method == "resources/list" {
			if len(idx.ResourcesResp) == 0 {
				idx.ResourcesResp = payload
			}
		} else if ev.Method == "prompts/list" {
			if len(idx.PromptsResp) == 0 {
				idx.PromptsResp = payload
			}
		} else {
			// Fallback heuristics if method string was omitted on the response event
			if bytes.Contains(payload, []byte(`"protocolVersion"`)) && len(idx.InitializeResp) == 0 {
				idx.InitializeResp = payload
			} else if (bytes.Contains(payload, []byte(`"tools":[`)) || bytes.Contains(payload, []byte(`"tools": [`))) && len(idx.ToolsListResp) == 0 {
				idx.ToolsListResp = payload
			}
		}

		// Store tool call responses
		if ev.ToolName != "" {
			idx.ToolResponses[ev.ToolName] = append(idx.ToolResponses[ev.ToolName], ev)
		}
		if ev.Method != "" {
			idx.MethodResponses[ev.Method] = append(idx.MethodResponses[ev.Method], ev)
		}
	}

	return idx
}

// MatchResponse returns the appropriate recorded response bytes and latency for a request.
func (idx *ReplayIndex) MatchResponse(method string, rawParams, reqID json.RawMessage) ([]byte, int64) {
	switch method {
	case "initialize":
		if len(idx.InitializeResp) > 0 {
			return substituteRPCID(idx.InitializeResp, reqID), 0
		}
		fallback := fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2024-11-05","capabilities":{"tools":{}},"serverInfo":{"name":"mcp-jail-replay","version":"0.5.0"}}}`, string(reqID))
		return []byte(fallback), 0

	case "tools/list":
		if len(idx.ToolsListResp) > 0 {
			return substituteRPCID(idx.ToolsListResp, reqID), 0
		}
		fallback := fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"result":{"tools":[]}}`, string(reqID))
		return []byte(fallback), 0

	case "resources/list":
		if len(idx.ResourcesResp) > 0 {
			return substituteRPCID(idx.ResourcesResp, reqID), 0
		}
		fallback := fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"result":{"resources":[]}}`, string(reqID))
		return []byte(fallback), 0

	case "prompts/list":
		if len(idx.PromptsResp) > 0 {
			return substituteRPCID(idx.PromptsResp, reqID), 0
		}
		fallback := fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"result":{"prompts":[]}}`, string(reqID))
		return []byte(fallback), 0

	case "tools/call":
		var p struct {
			Name string `json:"name"`
		}
		_ = json.Unmarshal(rawParams, &p)
		if list, ok := idx.ToolResponses[p.Name]; ok && len(list) > 0 {
			curr := idx.ToolIndices[p.Name]
			ev := list[curr]
			if curr+1 < len(list) {
				idx.ToolIndices[p.Name] = curr + 1
			}
			return substituteRPCID([]byte(ev.PayloadJSON), reqID), ev.LatencyMs
		}
		errResp := fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"error":{"code":-32601,"message":"Tool '%s' not found in recorded session"}}`, string(reqID), p.Name)
		return []byte(errResp), 0

	default:
		if list, ok := idx.MethodResponses[method]; ok && len(list) > 0 {
			curr := idx.MethodIndices[method]
			ev := list[curr]
			if curr+1 < len(list) {
				idx.MethodIndices[method] = curr + 1
			}
			return substituteRPCID([]byte(ev.PayloadJSON), reqID), ev.LatencyMs
		}
		errResp := fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"error":{"code":-32601,"message":"Method '%s' not found in recorded session"}}`, string(reqID), method)
		return []byte(errResp), 0
	}
}

func substituteRPCID(respJSON []byte, newID json.RawMessage) []byte {
	var m map[string]interface{}
	if err := json.Unmarshal(respJSON, &m); err != nil {
		return respJSON
	}
	var rawID interface{}
	if err := json.Unmarshal(newID, &rawID); err == nil {
		m["id"] = rawID
	}
	b, err := json.Marshal(m)
	if err != nil {
		return respJSON
	}
	return b
}

// RunReplay starts the JSON-RPC stdio mock server responding with recorded payloads.
func RunReplay(in io.Reader, out io.Writer, errOut io.Writer, rec *recorder.Recorder, sessionID string, simulateTiming bool) error {
	events, err := rec.GetEvents(recorder.EventFilter{
		SessionID: sessionID,
		Limit:     10000,
	})
	if err != nil {
		return fmt.Errorf("failed to load events for session %s: %w", sessionID, err)
	}
	if len(events) == 0 {
		return fmt.Errorf("session %s has no recorded events", sessionID)
	}

	index := BuildReplayIndex(events)
	fmt.Fprintf(errOut, "[mcp-jail-replay] Replaying session %s (%d events loaded). Ready for client connections...\n", sessionID, len(events))

	scanner := bufio.NewScanner(in)
	buf := make([]byte, 1024*1024)
	scanner.Buffer(buf, 10*1024*1024)

	for scanner.Scan() {
		line := scanner.Bytes()
		trimmed := bytes.TrimSpace(line)
		if len(trimmed) == 0 {
			continue
		}

		var req struct {
			JSONRPC string          `json:"jsonrpc"`
			ID      json.RawMessage `json:"id"`
			Method  string          `json:"method"`
			Params  json.RawMessage `json:"params"`
		}
		if err := json.Unmarshal(trimmed, &req); err != nil {
			continue
		}

		// Skip notifications (no response expected)
		if len(req.ID) == 0 || string(req.ID) == "null" {
			continue
		}

		respBytes, latencyMs := index.MatchResponse(req.Method, req.Params, req.ID)
		if simulateTiming && latencyMs > 0 {
			time.Sleep(time.Duration(latencyMs) * time.Millisecond)
		}

		_, _ = out.Write(respBytes)
		_, _ = out.Write([]byte("\n"))
	}

	return scanner.Err()
}

func init() {
	replayCmd.Flags().StringVar(&replayDB, "db", "", "Path to SQLite flight recorder database (default: ~/.mcp-jail/flight-recorder.db)")
	replayCmd.Flags().BoolVarP(&replayList, "list", "l", false, "List available recorded sessions")
	replayCmd.Flags().BoolVarP(&replayTiming, "timing", "t", false, "Simulate original latency from recorded session")
}
