package policy

import (
	"encoding/json"
	"fmt"
)

// MCPBlockTextContent matches the MCP content structure.
type MCPBlockTextContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// MCPBlockResult matches the MCP tools/call result with isError: true.
type MCPBlockResult struct {
	Content []MCPBlockTextContent `json:"content"`
	IsError bool                  `json:"isError"`
}

// MCPBlockResponse is the synthetic response returned when a tool call is blocked.
type MCPBlockResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      interface{}     `json:"id"`
	Result  *MCPBlockResult `json:"result,omitempty"`
}

// CreateBlockedResponse formats a valid JSON-RPC 2.0 MCP response with isError: true.
func CreateBlockedResponse(rpcID interface{}, ruleName, reason string) ([]byte, error) {
	text := fmt.Sprintf("[MCP-JAIL POLICY BLOCK] Tool execution denied by local firewall.\nRule violated: %s\nReason: %s\nAction required: Do not attempt to bypass this restriction. Inform the user or choose a safe alternative.",
		ruleName, reason)

	resp := MCPBlockResponse{
		JSONRPC: "2.0",
		ID:      rpcID,
		Result: &MCPBlockResult{
			Content: []MCPBlockTextContent{
				{
					Type: "text",
					Text: text,
				},
			},
			IsError: true,
		},
	}

	return json.Marshal(resp)
}
