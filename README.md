# mcp-jail

[![Go Version](https://img.shields.io/badge/go-1.23%2B-blue.svg)](https://golang.org)
[![Pure Go](https://img.shields.io/badge/pure--Go-standalone_binary-success.svg)](https://golang.org)
[![Documentation](https://img.shields.io/badge/docs-GitHub_Pages-blue.svg)](https://smford.github.io/mcp-jail/)
[![Release](https://img.shields.io/github/v/release/smford/mcp-jail?color=blue)](https://github.com/smford/mcp-jail/releases)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

`mcp-jail` is a lightweight security proxy and flight recorder for the **Model Context Protocol (MCP)**. It acts as a safety guard between your AI coding agents (such as Claude Code, Cursor, Antigravity, and Claude Desktop) and the MCP servers running on your machine.

It is built as a single standalone executable in 100% pure Go—meaning there are no external C libraries, no background database services, and no runtime dependencies to install. You just download the binary and run it immediately.

Interactive online documentation: [https://smford.github.io/mcp-jail/](https://smford.github.io/mcp-jail/).

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

## Why mcp-jail?

AI coding agents are powerful because they can use tools to read files, run terminal commands, and inspect system resources via MCP servers. But giving an autonomous AI agent direct access to your local system introduces serious risks:

### Problems It Solves
1. **Accidental File & System Destruction**: An autonomous agent attempting to clean up files or install packages might execute catastrophic commands like `rm -rf`, `git push --force`, or destructive cloud commands.
2. **Directory Escapes & Sensitive Data Exposure**: MCP tools can wander outside your repository workspace, reading sensitive keys and configurations in `~/.ssh`, `~/.aws`, `~/.kube`, or `.env` files.
3. **Secrets Leaking into AI Prompts**: Tool outputs (like database dumps, API error traces, or application logs) often contain live tokens, API keys, and passwords that get sent directly into third-party LLM cloud contexts.
4. **Runaway Loops & Surprise Billing**: An AI caught in a hallucination or retry loop can spam hundreds of tool calls per minute, burning through rate limits and racking up costly API token bills.
5. **Zero Visibility & Audit Trail**: Standard MCP connections run silently in the background. If something breaks or data changes unexpectedly, developers have no record of what tool was called, what arguments were passed, or what was returned.

### Benefits You Get
- **Autonomous Coding with Peace of Mind**: Confidently let AI agents run autonomous tasks knowing guardrails prevent destructive actions and keep the agent contained inside your project folder.
- **Graceful Self-Correction (No Crashing)**: When `mcp-jail` blocks a forbidden command or path, it returns a helpful, standard error message back to the LLM explaining *why* it was blocked so the AI can correct itself and choose a safe alternative without crashing your session.
- **Automatic Secret Scrubbing**: High-entropy strings, AWS keys, GitHub tokens, Slack keys, Stripe secrets, and private keys are scrubbed from outputs before they ever reach the model.
- **Circuit Breakers for Cost & Rate Limits**: Set hard limits on tool calls per minute, maximum session calls, and token budgets to stop runaway agents in their tracks.
- **Sub-Millisecond Flight Recorder**: Every tool call, argument, result, blocked attempt, and latency metric is automatically saved to a fast local SQLite log for instant auditing and debugging.
- **Zero-Friction Standalone Setup**: Single binary with no external C dependencies or database drivers required. Install via Homebrew or download the binary and prefix any existing MCP server command with `mcp-jail wrap --`.

---

## Key Highlights

- **Single Standalone Binary**: Built in 100% pure Go with no external C libraries or system dependencies—runs out of the box on macOS, Linux, and Windows.
- **Pure-Go SQLite Flight Recorder**: Built on an embedded SQLite engine (`modernc.org/sqlite`) with non-blocking asynchronous channel writes (<1ms stdio latency).
- **Filesystem Boundary Guard**: Resolves relative paths (`../`), symlinks, and home shortcuts (`~`) against allowed workspace roots. Denies `~/.aws/**`, `~/.ssh/**`, `~/.kube/**`, `/etc/**`, and `**/.env*`.
- **Command Argument Guard**: Regex filters preventing destructive shell commands (e.g. `rm -rf`, `curl | sh`, `git push --force`, `aws iam`, `terraform destroy`).
- **Outbound Secret Scrubber**: Scans child server outputs before they reach the LLM context, masking credentials into `[REDACTED_BY_MCP_JAIL:<TYPE>]`.
- **Real-Time Desktop & Webhook Alerts**: Native popup notifications (macOS Notification Center / Linux `notify-send`) and formatted webhooks for Slack, Discord, and SIEM on policy violations.
- **Graceful Self-Correction**: When a policy violation occurs, `mcp-jail` returns a valid MCP `tools/call` response with `isError: true` containing actionable feedback. This allows the LLM to self-correct without crashing the client session.
- **Strict Stdout Hygiene**: In `wrap` mode, `os.Stdout` is reserved exclusively for JSON-RPC 2.0 traffic. Internal proxy logs always route to `os.Stderr`.

---

## Installation

### Homebrew (macOS & Linux)
```bash
brew install smford/tap/mcp-jail
```

### Go Install
```bash
go install github.com/smford/mcp-jail/cmd/mcp-jail@latest
```

### From Source
```bash
git clone https://github.com/smford/mcp-jail.git
cd mcp-jail
make build
# Binary is located at bin/mcp-jail
```

---

## Quick Start

### 1. One-Click AI Client Setup
Automatically configure Claude Desktop, Cursor, Windsurf, or Google Antigravity to wrap all their configured MCP servers with `mcp-jail`:
```bash
mcp-jail install claude        # Configures Claude Desktop
mcp-jail install cursor        # Configures Cursor IDE
mcp-jail install windsurf      # Configures Windsurf IDE
mcp-jail install antigravity   # Configures Google Antigravity & Gemini (CLI and GUI)
```

### 2. Discover & Audit Installed MCP Servers
List all MCP servers installed across your AI clients and view their protection status:
```bash
mcp-jail list                  # Scan all supported AI clients (alias: mcp-jail servers)
mcp-jail list antigravity      # Filter by client (or claude, cursor, windsurf)
mcp-jail list --json           # Structured JSON output for automation
```

### 3. Initialize Configuration
Generate a security policy `.mcp-jail.yaml` tailored to your MCP workload using presets (`coding`, `database`, `github`, `homeassistant`, `minimal`, or `default`):
```bash
# View available security presets
mcp-jail init --list-presets

# Initialize with a preset
mcp-jail init --preset coding
mcp-jail init --preset database
```

### 4. Wrap Any MCP Server
Prepend `mcp-jail wrap --` to any MCP server command. Use `--isolate` to activate OS-level sandbox containerization:
```bash
mcp-jail wrap --isolate -- npx -y @modelcontextprotocol/server-filesystem /path/to/workspace
```

### 5. Test & Lint Security Policies
```bash
# Verify policy decisions without running an active MCP server
mcp-jail test-policy --tool write_file --args '{"path": "/etc/passwd"}'

# Statically audit a policy YAML for security anti-patterns
mcp-jail lint-policy .mcp-jail.yaml
```

### 6. Live Activity Monitor
Open another terminal to watch active MCP sessions, calls, and latency in real time:
```bash
mcp-jail top
```

### 7. Auto-Generate Policies with Learning Mode
Run an MCP server in learning mode to observe benign behavior and synthesize a least-privilege security policy:
```bash
mcp-jail learn -- npx -y @modelcontextprotocol/server-filesystem .
# Generates .mcp-jail.learned.yaml
```

### 8. Inspect Changes & Rollback Rogue Modifications
```bash
# View unified git-style diff of file modifications made during an agent session
mcp-jail diff

# Restore files back to pre-session snapshot state
mcp-jail rollback
```

### 9. Inspect Audit Logs & Metrics
```bash
# View recent intercepted calls, latency, and redactions
mcp-jail logs --tail 20

# Filter for policy violations only
mcp-jail logs --blocked-only

# View session statistics
mcp-jail stats
```

### 9. Secure Remote MCP Servers (HTTP / SSE)
```bash
mcp-jail proxy --listen :8080 --upstream https://mcp.internal.company.com/sse
```

### 10. Run via Docker
```bash
docker run --rm -p 8080:8080 ghcr.io/smford/mcp-jail:latest proxy --listen :8080 --upstream https://remote-mcp.internal/sse
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

### 4. Google Antigravity & Gemini (CLI & GUI)

One-click setup automatically discovers and secures MCP configurations for both the Antigravity CLI (`~/.gemini/antigravity-cli/mcp_config.json`) and Antigravity GUI (`~/.gemini/config/mcp_config.json`):

```bash
# One-click install for both CLI and GUI
mcp-jail install antigravity

# Or target individually:
mcp-jail install antigravity-cli
mcp-jail install antigravity-gui
```

Manual configuration in your `mcp_config.json`:

```json
{
  "mcpServers": {
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

See the [Real-World Security Walkthrough](docs/examples-homeassistant.md) for detailed sample calls, screenshot examples, and flight recorder logs.

---

## CLI Reference

### `mcp-jail init`
Generates a `.mcp-jail.yaml` policy file in the current working directory.
- `-p, --preset <name>`: Preset policy template (`coding`, `database`, `github`, `homeassistant`, `minimal`, `default`).
- `--list-presets`: List all available presets and their descriptions.
- `-f, --force`: Overwrite existing configuration file.

### `mcp-jail wrap [flags] -- <command> [args...]`
Transparently proxies stdin and stdout of the target MCP server command or remote HTTP endpoint.
- `--remote <url>`: URL of upstream remote MCP server to bridge via stdio.
- `--header <header>`: Custom HTTP header for upstream requests (e.g. `--header 'Authorization: Bearer xxx'`).
- `-c, --config <path>`: Path to `.mcp-jail.yaml` (default: `.mcp-jail.yaml` in current directory).
- `--db <path>`: Path to SQLite flight recorder database (default: `~/.mcp-jail/flight-recorder.db`).
- `--session-id <string>`: Custom session identifier (default: auto-generated UUID).
- `--dry-run`: Evaluate and log policy violations without blocking requests.
- `--isolate`: Activate OS-level sandbox containerization.

### `mcp-jail logs [flags]`
Prints an audit trail of tool invocations, policy blocks, and credential redactions.
- `-f, --follow`: Stream and follow incoming events in real time.
- `--session <id>`: Filter by session ID.
- `--blocked-only`: Show only events blocked by security rules.
- `--tail <n>`: Number of recent events to display (default: 50).
- `--db <path>`: SQLite database path (default: `~/.mcp-jail/flight-recorder.db`).

### `mcp-jail stats [flags]`
Displays cumulative metrics, token estimates, and top tools invoked.
- `--session <id>`: Filter stats for a specific session.
- `--db <path>`: SQLite database path (default: `~/.mcp-jail/flight-recorder.db`).

### `mcp-jail replay [session-id] [flags]`
Starts a mock MCP server that deterministically replays recorded JSON-RPC responses from a previous session stored in the SQLite flight recorder.
- `-l, --list`: List recorded sessions stored in the flight recorder.
- `-t, --timing`: Simulate original latency delays from recorded session.
- `--db <path>`: SQLite database path (default: `~/.mcp-jail/flight-recorder.db`).

### `mcp-jail diff [flags]`
Displays a git-style unified diff of all file modifications and creations made during an agent session.
- `--session <id>`: Filter diff by session ID (default: latest active session).
- `--db <path>`: SQLite database path (default: `~/.mcp-jail/flight-recorder.db`).

### `mcp-jail rollback [flags]`
Safely restores modified and deleted files back to their pre-session snapshot state.
- `--session <id>`: Session ID to rollback (default: latest active session).
- `-f, --force`: Bypass confirmation prompt and execute rollback immediately.
- `--db <path>`: SQLite database path (default: `~/.mcp-jail/flight-recorder.db`).

### `mcp-jail learn [flags] -- <command> [args...]`
Runs an MCP server in observation mode to passively monitor tool calls and auto-generate a tailored, least-privilege security policy.
- `-o, --output <path>`: Output policy file path (default: `.mcp-jail.learned.yaml`).
- `--duration <duration>`: Maximum learning observation time (e.g. `10m`, `1h`).

### `mcp-jail top [flags]`
Opens an interactive real-time terminal dashboard (TUI) displaying active MCP sessions, calls per minute, latency gauges, and recent policy blocks.
- `--interval <duration>`: Refresh rate interval (default: `1s`).
- `--db <path>`: SQLite database path (default: `~/.mcp-jail/flight-recorder.db`).

### `mcp-jail proxy [flags]`
Runs a transparent HTTP / Server-Sent Events (SSE) reverse proxy to protect remote and cloud-hosted MCP servers.
- `--listen <addr>`: Local listening address and port (default: `:8080`).
- `--upstream <url>`: Upstream remote MCP server endpoint URL.
- `-c, --config <path>`: Path to `.mcp-jail.yaml` policy file.

### `mcp-jail serve [flags]`
Runs an HTTP daemon providing health checks, Prometheus-compatible telemetry metrics, and JSON endpoints.
- `--listen <addr>`: HTTP daemon address (default: `:9090`).
- `--db <path>`: SQLite database path (default: `~/.mcp-jail/flight-recorder.db`).

### `mcp-jail list [client] [flags]`
Discovers and lists installed MCP servers across supported AI clients (Antigravity CLI & GUI, Claude Desktop, Cursor, Windsurf) and local project workspace configurations (`./.cursor/mcp.json`, `./.vscode/mcp.json`, `./mcp.json`) along with their protection status.
- Aliases: `servers`, `status`.
- `--json`: Output full details as structured JSON.
- `--path <path>`: Custom path to a specific configuration file to inspect.

### `mcp-jail doctor [flags]`
Runs comprehensive environment diagnostics, checks client configurations, verifies reachability of remote MCP servers, checks local command binaries in `$PATH`, audits `.mcp-jail.yaml` policy syntax, and validates SQLite database and OS sandboxing readiness.
- `--json`: Output full diagnostics report as structured JSON.

### `mcp-jail install <client>`
Automatically wraps configured MCP servers in popular AI desktop agents, CLIs, and local project workspaces.
- Supported clients: `claude` (Claude Desktop), `cursor` (Cursor IDE), `windsurf` (Windsurf IDE), `antigravity` / `gemini` (both Antigravity CLI and GUI), `antigravity-cli`, `antigravity-gui`, `workspace` (local project: `.cursor/mcp.json`, `.vscode/mcp.json`, `mcp.json`).
- `--dry-run`: Preview configuration changes without writing to disk.

### `mcp-jail uninstall <client>`
Restores original unwrapped MCP server commands in target AI desktop configurations or local project workspaces.
- Supported clients: `claude`, `cursor`, `windsurf`, `antigravity` / `gemini`, `antigravity-cli`, `antigravity-gui`, `workspace`.

### `mcp-jail test-policy [flags]`
Dry-runs and simulates policy evaluation against arbitrary tool calls, resource paths, or prompt injections without executing commands.
- `-c, --config <path>`: Path to policy configuration file.
- `--tool <name>`: Tool name to test.
- `--args <json>`: JSON arguments payload to evaluate.

### `mcp-jail lint-policy <file>`
Statically checks a policy YAML file for security anti-patterns, dangerous wildcards, overlapping rules, or missing safeguards.

### `mcp-jail version`
Prints the compiled version number, git commit hash, and build date.

---

## Policy Configuration (`.mcp-jail.yaml`)

```yaml
version: "1"

settings:
  dry_run: false
  log_level: "info"

# 1. Tool Allow/Deny List & Parameter Constraints
tools:
  allowed: [] # If non-empty, only matching tool names are permitted
  denied:
    - "^format_disk$"
    - "^drop_database$"
  rules:
    - tool: ".*sql.*"
      deny_args:
        query: "(?i)\\b(DROP|TRUNCATE|ALTER\\s+USER)\\b"
      reason: "Destructive SQL commands are blocked"
    - tool: "git_push"
      allow_args:
        branch: "^(feature/|fix/).*"
      reason: "Direct push to protected branches is blocked"

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

To verify standalone pure-Go compilation without external dependencies:
```bash
CGO_ENABLED=0 go build -o bin/mcp-jail ./cmd/mcp-jail
```

---

## License

MIT License. See [LICENSE](LICENSE) for details.
