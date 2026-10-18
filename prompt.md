You are a Principal Go Systems Engineer and Security Architect. Your task is to design, implement, and test `mcp-jail`, a single-binary, zero-CGO local firewall and flight-recorder proxy for Model Context Protocol (MCP) servers and terminal AI coding agents.

### 1. Problem & Core Architecture
AI coding agents (Claude Code, Antigravity, OpenCode, Cursor) execute MCP servers as local subprocesses communicating via line-delimited JSON-RPC 2.0 over `stdin` and `stdout`.
`mcp-jail` sits transparently between the Host Agent and the Target MCP Server:
[AI Host Agent] <--(stdio JSON-RPC)--> [mcp-jail] <--(stdio JSON-RPC)--> [Target MCP Server]

CRITICAL INVARIANT: When running in `wrap` mode, `mcp-jail` MUST NEVER write logs, panics, or debug output to `os.Stdout`. `os.Stdout` is strictly reserved for valid JSON-RPC 2.0 messages destined for the Host Agent. Any internal logging must go to `os.Stderr` or the SQLite flight recorder.

### 2. Tech Stack & Constraints
- Language: Go 1.23+
- Zero-CGO: Must compile with `CGO_ENABLED=0` for effortless cross-platform binary distribution.
- SQLite Driver: Use `modernc.org/sqlite` (pure Go SQLite).
- Config: YAML (`gopkg.in/yaml.v3`).
- TUI (`top` / `logs` mode): Use `github.com/charmbracelet/bubbletea` and `lipgloss` (or clean ANSI table rendering if keeping dependencies minimal).
- CLI Framework: Standard library `flag` or `github.com/spf13/cobra`.

### 3. CLI Interface Specification
Implement the following subcommands:
1. `mcp-jail init`
   - Generates a sensible default `.mcp-jail.yaml` in the current working directory with strict defaults (blocking `~/.aws`, `~/.ssh`, `~/.kube`, `.env*`, and destructive shell commands).
2. `mcp-jail wrap [flags] -- <command> [args...]`
   - Flags: `--config <path>`, `--db <path>` (default `~/.mcp-jail/flight-recorder.db`), `--session-id <string>`, `--dry-run`.
   - Spawns `<command> [args...]` as a child process with pipes attached to its `stdin`, `stdout`, and `stderr`.
   - Forwards `stderr` transparently.
   - Intercepts every JSON-RPC line on `stdin` (Host -> Server) and `stdout` (Server -> Host).
3. `mcp-jail logs [--session <id>] [--blocked-only] [--tail]`
   - Queries the SQLite flight recorder and prints a human-readable audit trail of tool calls, latency, redactions, and policy blocks.
4. `mcp-jail stats`
   - Prints session summaries: total tool calls, blocked calls, redacted secrets count, estimated token usage (approximated as `len(payload)/4`), and top tools invoked.

### 4. Firewall & Policy Engine (`.mcp-jail.yaml`)
When `mcp-jail` intercepts a `tools/call` request from the Host Agent, or a `tools/call` response from the MCP Server, it must pass through a chain of middleware:

1. Tool Allow/Deny List:
   - Block specific tool names or regex patterns (e.g., `bash`, `execute_command`, `write_file`).
2. Filesystem Boundary Enforcement:
   - Inspect all string values inside `params.arguments`.
   - Resolve relative paths (`../`) and symlinks against the current working directory.
   - Block if any path matches `denied_paths` globs (e.g., `**/.env*`, `~/.ssh/**`, `~/.aws/**`, `/etc/**`) or falls outside `allowed_roots` (defaulting to current workspace).
3. Command Argument Guard (for shell/exec tools):
   - Block dangerous patterns in arguments via regex (e.g., `rm -rf`, `curl .* \| sh`, `git push --force`, `aws iam`, `terraform destroy`).
4. Rate & Budget Limiter:
   - Track `max_tool_calls_per_minute` and `max_total_calls_per_session` to prevent runaway agent loops.
   - Track estimated cumulative response bytes/tokens (`max_session_tokens`).
5. Outbound Secret Scrubber (Response Filter):
   - Scan MCP Server responses BEFORE forwarding them to the Host Agent's `stdout`.
   - Automatically redact high-entropy secrets and known patterns (AWS Access Keys `AKIA...`, GitHub PATs `ghp_...`, Slack tokens, Private Keys `-----BEGIN...`, generic `API_KEY=...`) replacing them with `[REDACTED_BY_MCP_JAIL:<TYPE>]` so secrets never enter the LLM context window.

### 5. Blocking Behavior (Graceful JSON-RPC Error Injection)
When a `tools/call` request violates a policy, DO NOT forward the request to the child MCP server, and DO NOT crash the proxy. Instead, immediately synthesize and return a valid MCP `tools/call` response to the Host Agent on `stdout` using the request's `id` with this exact JSON structure:

{
  "jsonrpc": "2.0",
  "id": "<request_id>",
  "result": {
    "content": [
      {
        "type": "text",
        "text": "[MCP-JAIL POLICY BLOCK] Tool execution denied by local firewall.\nRule violated: <rule_name>\nReason: <detailed_reason>\nAction required: Do not attempt to bypass this restriction. Inform the user or choose a safe alternative."
      }
    ],
    "isError": true
  }
}

(Note: Returning `result` with `isError: true` rather than a protocol-level JSON-RPC `error` allows the LLM agent to read the explanation and self-correct gracefully without crashing the MCP client session).

### 6. SQLite Flight Recorder Schema
Store all intercepted events asynchronously (via a buffered Go channel worker so stdio latency remains under 1ms) in SQLite:
- `sessions`: `id`, `started_at`, `ended_at`, `command`, `cwd`, `total_calls`, `blocked_calls`, `redacted_secrets`, `est_tokens`
- `events`: `id`, `session_id`, `timestamp`, `direction` (`host_to_server` | `server_to_host`), `rpc_id`, `method`, `tool_name`, `action` (`allowed` | `blocked` | `redacted`), `rule_triggered`, `latency_ms`, `payload_json` (always store the redacted version so the audit DB itself does not leak secrets).

### 7. Project Layout
Organize the repository cleanly:
- `cmd/mcp-jail/main.go`
- `internal/config/` (YAML schema, loader, and `init` default template)
- `internal/proxy/` (Subprocess runner, stdio buffered scanners supporting 16MB+ lines, JSON-RPC router)
- `internal/policy/` (Path traversal resolver, command regexes, rate/token circuit breaker)
- `internal/scrubber/` (Secret regexes + entropy detector for server responses)
- `internal/recorder/` (Pure-Go SQLite schema, async batch writer, query methods)
- `internal/cli/` (Subcommands: `wrap`, `init`, `logs`, `stats`)
- `testdata/mock_mcp_server.go` (A tiny standalone Go MCP server used for integration testing)
- `README.md` and `Makefile`

### 8. Execution Plan & Verification Steps
Execute this build iteratively and verify every stage using terminal tools:
1. Step 1 (Scaffold & Config): Initialize `go.mod`, create directory structure, implement `internal/config` with default rules, and verify `go build ./...`.
2. Step 2 (Policy & Scrubber Unit Tests): Implement `internal/policy` (path resolution, glob matching, rate limiting, token estimation) and `internal/scrubber` (secret redaction). Write comprehensive table-driven unit tests (`policy_test.go`, `scrubber_test.go`) and run `go test ./internal/...`.
3. Step 3 (SQLite Flight Recorder): Implement `internal/recorder` with `modernc.org/sqlite`. Write unit tests verifying concurrent event logging and querying.
4. Step 4 (STDIO Proxy Engine): Implement `internal/proxy`. Ensure `bufio.Scanner` buffer sizes are configured to handle up to 16MB JSON-RPC payloads without failing with `bufio.Scanner: token too long`. Ensure correlation of `request.id` between `host_to_server` and `server_to_host` to calculate tool execution latency and inspect responses.
5. Step 5 (End-to-End Integration Test): Build `testdata/mock_mcp_server.go` that responds to `tools/call` requests (e.g., reading a dummy file, returning a fake AWS key `AKIAIOSFODNN7EXAMPLE`, or echoing a command). Write an integration test in `internal/proxy/proxy_test.go` that spawns `mcp-jail` wrapping the mock server, sends JSON-RPC messages over `stdin`, and asserts:
   - Safe tool calls succeed and are logged in SQLite.
   - Requests targeting `../.env` or `~/.aws/credentials` are blocked with `isError: true` and never reach the mock server.
   - Fake AWS keys in the mock server's output are scrubbed before reaching `stdout`.
   - Exceeding the session call limit trips the circuit breaker.
6. Step 6 (CLI Polish & Docs): Wire up `cmd/mcp-jail/main.go`, create a `Makefile` (`build`, `test`, `lint`), and write a crisp `README.md` showing exact configuration snippets for wrapping MCP servers in Claude Desktop, Claude Code, Antigravity, and Cursor (`mcp.json`).

Begin by inspecting the workspace, initializing the Go module, and starting Step 1. Run tests at every step before proceeding.
