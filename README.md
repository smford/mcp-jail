# mcp-jail

[![Go Version](https://img.shields.io/badge/go-1.23%2B-blue.svg)](https://golang.org)
[![Zero CGO](https://img.shields.io/badge/CGO-disabled-success.svg)](https://golang.org)
[![Documentation](https://img.shields.io/badge/docs-GitHub_Pages-blue.svg)](https://smford.github.io/mcp-jail/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

`mcp-jail` is a high-performance, zero-CGO local firewall and flight-recorder proxy for the **Model Context Protocol (MCP)**. It sits transparently between your AI host agent (Claude Code, Antigravity, Cursor, Claude Desktop) and target MCP servers running locally.

Interactive online documentation is available at [https://smford.github.io/mcp-jail/](https://smford.github.io/mcp-jail/).

```
[ AI Host Agent ]
  (Claude / Antigravity / Cursor)
         │
         │  stdio JSON-RPC 2.0
         ▼
 ┌──────────────────────────────────────────────────────────────┐
 │                          mcp-jail                            │
 │                                                              │
 │  [ Policy Engine ]        [ Secret Scrubber ]                │
 │   • Tool Allow/Deny        • Redacts AWS keys (AKIA...)      │
 │   • Path Traversal Guard   • Redacts GitHub PATs (ghp_...)   │
 │   • Symlink Resolver       • Redacts Private Keys            │
 │   • Command Guard (rm -rf) • Redacts Slack / Stripe tokens   │
 │   • Rate & Token Limiter   • Shannon Entropy Scanner         │
 │                                                              │
 │  [ SQLite Flight Recorder ] (Async worker, <1ms overhead)    │
 │   • Sessions, events, latency, redactions, audit trail       │
 └──────────────────────────────────────────────────────────────┘
         │
         │  stdio JSON-RPC 2.0
         ▼
[ Target MCP Server ]
  (filesystem, bash, postgres, github, etc.)
```

---

## Key Highlights

- **Zero-CGO & Single Binary**: Compiles with `CGO_ENABLED=0` for pure Go cross-platform distribution.
- **Pure-Go SQLite Flight Recorder**: Built on `modernc.org/sqlite` with asynchronous channel writes (<1ms stdio latency).
- **Filesystem Boundary Guard**: Resolves relative paths (`../`), symlinks, and home shortcuts (`~`) against allowed workspace roots. Denies `~/.aws/**`, `~/.ssh/**`, `~/.kube/**`, `/etc/**`, and `**/.env*`.
- **Command Argument Guard**: Regex filters preventing destructive shell commands (e.g. `rm -rf`, `curl | sh`, `git push --force`, `aws iam`, `terraform destroy`).
- **Outbound Secret Scrubber**: Scans child server outputs before they reach the LLM context, masking credentials into `[REDACTED_BY_MCP_JAIL:<TYPE>]`.
- **Graceful Self-Correction**: When a policy violation occurs, `mcp-jail` returns a valid MCP `tools/call` response with `isError: true` containing actionable feedback. This allows the LLM to self-correct without crashing the client session.
- **Strict Stdout Hygiene**: In `wrap` mode, `os.Stdout` is reserved exclusively for JSON-RPC 2.0 traffic. Internal proxy logs always route to `os.Stderr`.

---

## Installation

### From Source
```bash
git clone https://github.com/smford/mcp-jail.git
cd mcp-jail
make build
# Binary is located at bin/mcp-jail
```

### Go Install
```bash
go install github.com/smford/mcp-jail/cmd/mcp-jail@latest
```

---

## Quick Start

### 1. Initialize Configuration
Generate a strict default `.mcp-jail.yaml` in your project root:
```bash
mcp-jail init
```

### 2. Wrap Any MCP Server
Prepend `mcp-jail wrap --` to any MCP server command:
```bash
mcp-jail wrap -- npx -y @modelcontextprotocol/server-filesystem /path/to/workspace
```

### 3. Inspect Live Audit Logs
```bash
# View recent intercepted calls, latency, and redactions
mcp-jail logs

# Filter for policy violations only
mcp-jail logs --blocked-only
```

### 4. View Session Statistics
```bash
mcp-jail stats
```

---

## Interactive Documentation

Full interactive documentation rendered with [`md-web-renderer`](https://github.com/smford/md-web-renderer) is deployed via GitHub Actions:

- **Live Documentation**: [https://smford.github.io/mcp-jail/](https://smford.github.io/mcp-jail/)
- **Documentation Source**: [`docs/`](docs/)
  - [Getting Started](docs/getting-started.md)
  - [Architecture & Design](docs/architecture.md)
  - [Policy & Firewall Engine](docs/policy-engine.md)
  - [Outbound Secret Scrubber](docs/secret-scrubber.md)
  - [SQLite Flight Recorder](docs/flight-recorder.md)
  - [Client Integrations](docs/clients.md)
  - [CLI Reference](docs/cli-reference.md)

To preview the documentation locally with search, table of contents, and interactive Mermaid diagrams:

```bash
make docs-serve
# Opens local server at http://localhost:8000
```

---

## Client Integration Examples

### 1. Claude Desktop (`claude_desktop_config.json`)

On macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`  
On Windows: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "/usr/local/bin/mcp-jail",
      "args": [
        "wrap",
        "--config", "/Users/alice/projects/app/.mcp-jail.yaml",
        "--",
        "npx",
        "-y",
        "@modelcontextprotocol/server-filesystem",
        "/Users/alice/projects/app"
      ]
    }
  }
}
```

### 2. Cursor (`mcp.json`)

Place in `~/.cursor/mcp.json` or `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "terminal": {
      "command": "mcp-jail",
      "args": [
        "wrap",
        "--",
        "uvx",
        "mcp-server-commands"
      ]
    }
  }
}
```

### 3. Claude Code

When starting or configuring Claude Code with MCP servers:

```bash
claude mcp add secure-fs -- mcp-jail wrap -- npx -y @modelcontextprotocol/server-filesystem .
```

### 4. Google Antigravity

In your Antigravity agent configuration or `mcp_settings.json`:

```json
{
  "servers": {
    "local-exec": {
      "command": "mcp-jail",
      "args": [
        "wrap",
        "--config", ".mcp-jail.yaml",
        "--",
        "node",
        "./server.js"
      ]
    }
  }
}
```

---

## CLI Reference

### `mcp-jail init`
Generates a default `.mcp-jail.yaml` in the current working directory.
- `-f, --force`: Overwrite existing configuration file.

### `mcp-jail wrap [flags] -- <command> [args...]`
Transparently proxies stdin and stdout of the target MCP server command.
- `-c, --config <path>`: Path to `.mcp-jail.yaml` (default: `.mcp-jail.yaml` in current directory).
- `--db <path>`: Path to SQLite flight recorder database (default: `~/.mcp-jail/flight-recorder.db`).
- `--session-id <string>`: Custom session identifier (default: auto-generated UUID).
- `--dry-run`: Evaluate and log policy violations without blocking requests.

### `mcp-jail logs [flags]`
Prints an audit trail of tool invocations, policy blocks, and credential redactions.
- `--session <id>`: Filter by session ID.
- `--blocked-only`: Show only events blocked by security rules.
- `--tail <n>`: Number of recent events to display (default: 50).
- `--db <path>`: SQLite database path (default: `~/.mcp-jail/flight-recorder.db`).

### `mcp-jail stats [flags]`
Displays cumulative metrics, token estimates, and top tools invoked.
- `--session <id>`: Filter stats for a specific session.
- `--db <path>`: SQLite database path (default: `~/.mcp-jail/flight-recorder.db`).

---

## Policy Configuration (`.mcp-jail.yaml`)

```yaml
version: "1"

settings:
  dry_run: false
  log_level: "info"

# 1. Tool Allow/Deny List
tools:
  allowed: [] # If non-empty, only matching tool names are permitted
  denied:
    - "^format_disk$"
    - "^drop_database$"

# 2. Filesystem Boundary Enforcement
filesystem:
  enabled: true
  allowed_roots:
    - "."     # Resolves to current workspace
  denied_paths:
    - "**/.env*"
    - "~/.ssh/**"
    - "~/.aws/**"
    - "~/.kube/**"
    - "/etc/**"
    - "/var/run/**"
    - "~/.gnupg/**"
    - "**/*id_rsa*"
    - "**/*id_ed25519*"
    - "**/*.pem"
    - "**/*.key"

# 3. Command Argument Guard
commands:
  enabled: true
  denied_patterns:
    - 'rm\s+(-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r)\s+.*'
    - 'rm\s+-rf\s+.*'
    - 'curl\s+.*\|\s*(ba)?sh'
    - 'wget\s+.*\|\s*(ba)?sh'
    - 'git\s+push\s+.*--force'
    - 'aws\s+iam\s+.*'
    - 'terraform\s+destroy'
    - 'mkfs\..*'
    - 'dd\s+if=.*'
    - 'chmod\s+(-R\s+)?777\s+/'

# 4. Rate & Budget Limiter
limits:
  max_tool_calls_per_minute: 60
  max_total_calls_per_session: 100
  max_session_tokens: 500000

# 5. Outbound Secret Scrubber
scrubber:
  enabled: true
  redact_patterns: true
  redact_entropy: true
  custom_patterns: []
```

---

## Graceful Policy Block Response

When an action is blocked, `mcp-jail` generates an in-protocol JSON-RPC response with `isError: true` on `stdout`:

```json
{
  "jsonrpc": "2.0",
  "id": 42,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "[MCP-JAIL POLICY BLOCK] Tool execution denied by local firewall.\nRule violated: filesystem_boundary\nReason: Access to path \"~/.ssh/id_rsa\" is denied by pattern \"/Users/alice/.ssh/**\"\nAction required: Do not attempt to bypass this restriction. Inform the user or choose a safe alternative."
      }
    ],
    "isError": true
  }
}
```

This ensures the AI agent understands the refusal rationale and continues solving problems without aborting the session.

---

## Testing & Quality Assurance

Run the test suite including unit tests and end-to-end integration tests with the mock MCP server:

```bash
make test
```

To run with coverage:
```bash
make test-coverage
```

To verify zero-CGO compilation:
```bash
CGO_ENABLED=0 go build -o bin/mcp-jail ./cmd/mcp-jail
```

---

## License

MIT License. See [LICENSE](LICENSE) for details.