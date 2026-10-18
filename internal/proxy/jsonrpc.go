package proxy

import (
	"encoding/json"
	"strings"
)

// JSONRPCMessage is a lightweight envelope for JSON-RPC 2.0 messages.
type JSONRPCMessage struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   json.RawMessage `json:"error,omitempty"`
}

// ToolCallParams decodes parameters for a tools/call method.
type ToolCallParams struct {
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments"`
}

// ParseMessage parses a raw line into a JSONRPCMessage.
func ParseMessage(data []byte) (*JSONRPCMessage, error) {
	var msg JSONRPCMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil, err
	}
	return &msg, nil
}

// ParseToolCallParams unmarshals params for a tools/call request.
func (m *JSONRPCMessage) ParseToolCallParams() (*ToolCallParams, error) {
	if len(m.Params) == 0 {
		return &ToolCallParams{Arguments: make(map[string]interface{})}, nil
	}
	var params ToolCallParams
	if err := json.Unmarshal(m.Params, &params); err != nil {
		return nil, err
	}
	if params.Arguments == nil {
		params.Arguments = make(map[string]interface{})
	}
	return &params, nil
}

// IDString returns a string representation of the RPC ID for map indexing and logging.
func (m *JSONRPCMessage) IDString() string {
	raw := strings.TrimSpace(string(m.ID))
	if raw == "" || raw == "null" {
		return ""
	}
	// Strip surrounding quotes if string
	if strings.HasPrefix(raw, `"`) && strings.HasSuffix(raw, `"`) && len(raw) >= 2 {
		return raw[1 : len(raw)-1]
	}
	return raw
}
