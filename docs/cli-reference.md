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

Generates a sensible default `.mcp-jail.yaml` policy file in the current working directory.

```bash
mcp-jail init [flags]
```

### Flags

| Flag | Short | Type | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `--force` | `-f` | bool | `false` | Overwrite existing `.mcp-jail.yaml` file if present |

---

## `mcp-jail wrap`

Proxies standard I/O streams of the target MCP server command, enforcing firewall policies and scrubbing outbound credentials.

```bash
mcp-jail wrap [flags] -- <command> [args...]
```

### Flags

| Flag | Short | Type | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
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
