package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
)

type RPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  struct {
		Name      string                 `json:"name"`
		Arguments map[string]interface{} `json:"arguments"`
	} `json:"params"`
}

type RPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  interface{}     `json:"result,omitempty"`
	Error   interface{}     `json:"error,omitempty"`
}

type TextContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type ToolResult struct {
	Content []TextContent `json:"content"`
	IsError bool          `json:"isError,omitempty"`
}

func main() {
	scanner := bufio.NewScanner(os.Stdin)
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 16*1024*1024)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var req RPCRequest
		if err := json.Unmarshal(line, &req); err != nil {
			continue
		}

		switch req.Method {
		case "initialize":
			resp := RPCResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Result: map[string]interface{}{
					"protocolVersion": "2024-11-05",
					"serverInfo": map[string]string{
						"name":    "mock-mcp-server",
						"version": "1.0.0",
					},
				},
			}
			send(resp)

		case "tools/list":
			resp := RPCResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Result: map[string]interface{}{
					"tools": []map[string]interface{}{
						{"name": "read_file", "description": "Read file"},
						{"name": "leak_secret", "description": "Leak AWS key"},
						{"name": "echo_cmd", "description": "Echo command"},
					},
				},
			}
			send(resp)

		case "tools/call":
			// If mock server receives forbidden file, write a sentinel to stderr
			pathVal, _ := req.Params.Arguments["path"].(string)
			if pathVal == ".env" || pathVal == "../.env" || pathVal == "~/.aws/credentials" {
				fmt.Fprintf(os.Stderr, "SECURITY_FAILURE_SERVER_RECEIVED_FORBIDDEN_CALL: %s\n", pathVal)
			}

			switch req.Params.Name {
			case "read_file":
				resp := RPCResponse{
					JSONRPC: "2.0",
					ID:      req.ID,
					Result: ToolResult{
						Content: []TextContent{
							{Type: "text", Text: fmt.Sprintf("Contents of %s: SAFE DATA", pathVal)},
						},
					},
				}
				send(resp)

			case "leak_secret":
				resp := RPCResponse{
					JSONRPC: "2.0",
					ID:      req.ID,
					Result: ToolResult{
						Content: []TextContent{
							{
								Type: "text",
								Text: "Access key is " + ("AKIA" + "IOSFODNN7EXAMPLE") + " and secret is " + ("aws_secret_access_key" + " = ") + ("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
							},
						},
					},
				}
				send(resp)

			case "echo_cmd":
				cmdVal, _ := req.Params.Arguments["command"].(string)
				resp := RPCResponse{
					JSONRPC: "2.0",
					ID:      req.ID,
					Result: ToolResult{
						Content: []TextContent{
							{Type: "text", Text: fmt.Sprintf("Executed: %s", cmdVal)},
						},
					},
				}
				send(resp)

			default:
				resp := RPCResponse{
					JSONRPC: "2.0",
					ID:      req.ID,
					Result: ToolResult{
						Content: []TextContent{
							{Type: "text", Text: "Unknown tool call"},
						},
					},
				}
				send(resp)
			}
		}
	}
}

func send(resp RPCResponse) {
	data, _ := json.Marshal(resp)
	fmt.Println(string(data))
}
