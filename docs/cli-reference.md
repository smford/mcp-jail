# CLI Reference

Reference guide for all `mcp-jail` subcommands and options.

---

## `mcp-jail`

```
Usage:
  mcp-jail [command]

Available Commands:
  init         Generate default .mcp-jail.yaml security policy configuration
  wrap         Wrap and monitor an MCP server command with security boundaries
  list         List installed MCP servers across AI clients and their protection status
  doctor       Run comprehensive system diagnostics, server connectivity, and policy audits
  logs         View flight recorder audit trail of tool calls and policy blocks
  stats        Print session metrics, policy violations, and token estimates
  diff         Display unified diff of file mutations from an agent session
  rollback     Revert file changes from an agent session to pre-execution state
  learn        Auto-generate security policy by observing server behavior
  top          Interactive terminal monitor of active sessions and metrics
  proxy        Run HTTP/SSE reverse proxy for remote MCP servers
  install      Configure AI clients (Claude, Cursor, Windsurf) to wrap servers
  uninstall    Unwrap and restore original MCP server configurations
  test-policy  Simulate and test policy decisions for tools, resources, and prompts
  lint-policy  Audit a policy YAML file for dangerous patterns and misconfigurations
  version      Print version, copyright, and license information
  license      Print copyright and full license terms
  help         Help about any command
```

---

## `mcp-jail init`

Generates a `.mcp-jail.yaml` policy file in the current working directory, with optional security presets tailored to specific server types.

```bash
mcp-jail init [flags]
```

### Flags

| Flag | Short | Type | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `--preset` | `-p` | string | `default` | Security preset: `coding`, `database`, `github`, `homeassistant`, `minimal`, or `default` |
| `--list-presets` | | bool | `false` | List all available security presets with their descriptions and rules |
| `--force` | `-f` | bool | `false` | Overwrite existing `.mcp-jail.yaml` file if present |

### Presets Overview

- **`coding`**: Protects dev workspaces (Cursor, Claude Code, Antigravity, VS Code). Restricts branch pushes, blocks sensitive dotfiles (`.env`, `~/.ssh`, `~/.aws`, `~/.gnupg`), and stops dangerous shell commands (`rm -rf`, `curl | sh`).
- **`database`**: Protects SQL/data MCP servers (PostgreSQL, MySQL, SQLite, Supabase, Snowflake, BigQuery). Blocks unconstrained `DROP`, `TRUNCATE`, and unqualified `DELETE`; enforces rate limits and output token budgets.
- **`github`**: Protects Git and GitHub MCP servers. Blocks pushing to `main`/`master`, prevents repository deletion and dismissal of PR reviews, and redacts personal access tokens.
- **`homeassistant`**: Protects smart home / IoT servers. Denies access to door locks, alarms, and sirens, and constrains thermostat temperatures.
- **`minimal`**: Lightweight baseline policy with minimal restrictions, ideal for quick testing.
- **`default`**: Standard balanced baseline policy.

---

## `mcp-jail wrap`

Proxies standard I/O streams of the target MCP server command or remote HTTP endpoint, enforcing firewall policies and scrubbing outbound credentials.

```bash
# Wrap a local command:
mcp-jail wrap [flags] -- <command> [args...]

# Bridge a remote HTTP / SSE server via stdio:
mcp-jail wrap [flags] --remote <url> [--header "Header: Value"]...
```

### Flags

| Flag | Short | Type | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `--remote` | | string | `""` | URL of upstream remote MCP server to bridge via stdio |
| `--header` | | string | `""` | Custom HTTP header for upstream requests (can be specified multiple times) |
| `--config` | `-c` | string | `""` | Path to `.mcp-jail.yaml` (defaults to current directory) |
| `--db` | | string | `~/.mcp-jail/flight-recorder.db` | Path to SQLite flight recorder database |
| `--session-id` | | string | Auto UUID | Identifier for the recording session |
| `--dry-run` | | bool | `false` | Evaluate and log policy violations without blocking calls |
| `--isolate` | | bool | `false` | Enable OS-level subprocess sandboxing (sandbox-exec on macOS, bwrap on Linux) |

---

## `mcp-jail logs`

Queries the SQLite flight recorder and displays a human-readable audit trail.

```bash
mcp-jail logs [flags]
```

### Flags

| Flag | Short | Type | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `--format` | | string | `table` | Output format: `table`, `json`, `cef`, or `logfmt` |
| `--follow` | `-f` | bool | `false` | Stream and follow incoming events in real time |
| `--session` | | string | `""` | Filter events to a specific session ID |
| `--blocked-only` | | bool | `false` | Show only events blocked by security rules |
| `--tail` | | int | `50` | Number of most recent events to display |
| `--db` | | string | `~/.mcp-jail/flight-recorder.db` | Path to SQLite flight recorder database |

---

## `mcp-jail stats`

Calculates and displays summary metrics from the flight recorder.

```bash
mcp-jail stats [flags]
```

### Flags

| Flag | Short | Type | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `--session` | | string | `""` | Restrict statistics to a specific session ID |
| `--db` | | string | `~/.mcp-jail/flight-recorder.db` | Path to SQLite flight recorder database |

---

## `mcp-jail diff`

Displays a unified diff of all file changes captured during an AI agent session.

```bash
mcp-jail diff [session-id] [flags]
```

### Flags

| Flag | Short | Type | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `--db` | | string | `~/.mcp-jail/flight-recorder.db` | Path to SQLite flight recorder database |

---

## `mcp-jail rollback`

Reverts all file modifications from an AI agent session back to their pre-session snapshot states.

```bash
mcp-jail rollback [session-id] [flags]
```

### Flags

| Flag | Short | Type | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `--db` | | string | `~/.mcp-jail/flight-recorder.db` | Path to SQLite flight recorder database |

---

## `mcp-jail learn`

Runs an MCP server in permissive learning mode, observing all tool calls, paths, and commands to auto-generate a tailored `.mcp-jail.learned.yaml` security policy.

```bash
mcp-jail learn [flags] -- <command> [args...]
```

### Flags

| Flag | Short | Type | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `--output` | `-o` | string | `.mcp-jail.learned.yaml` | Output file for the generated policy YAML |
| `--config` | `-c` | string | `""` | Base policy configuration file to augment |
| `--db` | | string | `~/.mcp-jail/flight-recorder.db` | Path to SQLite flight recorder database |

---

## `mcp-jail top`

Launches a live terminal monitor displaying real-time active sessions, tool call streams, policy blocks, and latency metrics.

```bash
mcp-jail top [flags]
```

### Flags

| Flag | Short | Type | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `--interval` | `-i` | int | `1` | Dashboard refresh interval in seconds |
| `--once` | | bool | `false` | Render a single snapshot and exit |
| `--db` | | string | `~/.mcp-jail/flight-recorder.db` | Path to SQLite flight recorder database |

---

## `mcp-jail proxy`

Runs an HTTP and Server-Sent Events (SSE) reverse proxy to secure remote or cloud-hosted MCP servers.

```bash
mcp-jail proxy [flags]
```

### Flags

| Flag | Short | Type | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `--upstream` | `-u` | string | `""` | URL of upstream remote MCP server (required) |
| `--listen` | `-l` | string | `:8080` | Local address and port to bind |
| `--config` | `-c` | string | `""` | Path to policy configuration file |
| `--db` | | string | `~/.mcp-jail/flight-recorder.db` | Path to SQLite flight recorder database |

---

## `mcp-jail list`

Discovers and lists all MCP servers configured across supported AI clients (Google Antigravity CLI, Google Antigravity GUI / IDE, Claude Desktop, Cursor, Windsurf). Displays whether each server is currently protected by `mcp-jail`, running unprotected, or connected to a remote URL.

```bash
mcp-jail list [client] [flags]
```

Aliases: `servers`, `status`.

### Supported `<client>` values for filtering:
- `claude` - Claude Desktop
- `cursor` - Cursor IDE
- `windsurf` - Windsurf IDE
- `antigravity` / `gemini` - Both Antigravity CLI and GUI
- `antigravity-cli` / `gemini-cli` - Antigravity CLI only
- `antigravity-gui` / `gemini-gui` - Antigravity GUI only
- `workspace` / `local` - Local project repository configurations (`./.cursor/mcp.json`, `./.vscode/mcp.json`, `./mcp.json`)

### Flags

| Flag | Short | Type | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `--json` | | bool | `false` | Output server list in JSON format |
| `--path` | | string | `""` | Custom path to a client configuration file |

---

## `mcp-jail doctor`

Runs comprehensive environment diagnostics, checks client configurations, verifies reachability of remote MCP servers, checks local command binaries in `$PATH`, audits `.mcp-jail.yaml` policy syntax, checks SQLite database integrity, and validates kernel sandboxing readiness (`sandbox-exec` / `bwrap`).

```bash
mcp-jail doctor [flags]
```

### Flags

| Flag | Short | Type | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `--json` | | bool | `false` | Output diagnostics in structured JSON format |

---

## `mcp-jail install`

Automatically configures AI client configuration files (Claude Desktop, Cursor, Windsurf, Google Antigravity / Gemini CLI & GUI) to wrap configured MCP servers with `mcp-jail`. Creates an automatic backup file (`.mcp-jail.bak`) before modifying the config.

```bash
mcp-jail install <client> [flags]
```

Supported `<client>` values:
- `claude` - Claude Desktop
- `cursor` - Cursor IDE
- `windsurf` - Windsurf IDE
- `antigravity` / `gemini` - Both Antigravity CLI and GUI
- `antigravity-cli` / `gemini-cli` - Antigravity CLI only (`~/.gemini/antigravity-cli/mcp_config.json`)
- `antigravity-gui` / `gemini-gui` - Antigravity GUI only (`~/.gemini/config/mcp_config.json`)
- `workspace` - Current project workspace (`./.cursor/mcp.json`, `./.vscode/mcp.json`, `./mcp.json`)

### Flags

| Flag | Short | Type | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `--server` | | string | `""` | Wrap only a specific server name (defaults to all servers) |
| `--path` | | string | `""` | Custom path to client configuration file |

---

## `mcp-jail uninstall`

Restores original MCP server commands by removing the `mcp-jail` wrapper from client configuration files.

```bash
mcp-jail uninstall <client> [flags]
```

Supported `<client>` values:
- `claude` - Claude Desktop
- `cursor` - Cursor IDE
- `windsurf` - Windsurf IDE
- `antigravity` / `gemini` - Both Antigravity CLI and GUI
- `antigravity-cli` / `gemini-cli` - Antigravity CLI only
- `antigravity-gui` / `gemini-gui` - Antigravity GUI only
- `workspace` - Current project workspace (`./.cursor/mcp.json`, `./.vscode/mcp.json`, `./mcp.json`)

### Flags

| Flag | Short | Type | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `--server` | | string | `""` | Unwrap only a specific server name (defaults to all servers) |
| `--path` | | string | `""` | Custom path to client configuration file |

---

## `mcp-jail test-policy`

Simulates security policy evaluation without running an active MCP server. Validates tool permissions, path boundaries, resource URIs, or prompt templates.

```bash
mcp-jail test-policy [flags]
```

### Flags

| Flag | Short | Type | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `--config` | `-c` | string | `""` | Path to `.mcp-jail.yaml` policy configuration |
| `--tool` | | string | `""` | Tool name to test (e.g. `bash`, `write_file`) |
| `--args` | | string | `""` | JSON string of tool arguments (e.g. `'{"path": "/etc/passwd"}'`) |
| `--resource` | | string | `""` | Resource URI to test (e.g. `file:///etc/shadow`) |
| `--prompt` | | string | `""` | Prompt template name to test |

---

## `mcp-jail lint-policy`

Statically audits an `.mcp-jail.yaml` policy file for security anti-patterns, overly broad allowed roots, disabled scrubbers, or evasion vectors.

```bash
mcp-jail lint-policy [file] [flags]
```

### Flags

| Flag | Short | Type | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `--config` | `-c` | string | `""` | Path to `.mcp-jail.yaml` configuration file |

---

## `mcp-jail replay`

Starts a mock MCP server that deterministically replays recorded JSON-RPC responses from a previous session stored in the SQLite flight recorder.

Can be plugged directly into Claude Desktop, Cursor, Antigravity, or CI test suites to reproduce tool calls and errors without running actual child servers, consuming API tokens, or touching live environments.

```bash
# List available recorded sessions:
mcp-jail replay --list

# Replay a specific session over stdio:
mcp-jail replay <session-id>

# Replay with original latency timing simulated:
mcp-jail replay <session-id> --timing
```

### Flags

| Flag | Short | Type | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `--list` | `-l` | bool | `false` | List available recorded sessions and exit |
| `--timing` | `-t` | bool | `false` | Simulate original latency delays from recorded session |
| `--db` | | string | `""` | Path to SQLite flight recorder database |

---

## `mcp-jail version`

Prints the compiled version number, build metadata, copyright, and license information.

```bash
mcp-jail version
```

---

## `mcp-jail license`

Prints the copyright notice and full text of the open-source MIT License.

```bash
mcp-jail license
```
