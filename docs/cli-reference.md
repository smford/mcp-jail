# CLI Reference

Reference guide for all `mcp-jail` subcommands and options.

---

## `mcp-jail`

```
Usage:
  mcp-jail [command]

Available Commands:
  init        Generate default .mcp-jail.yaml security policy configuration
  wrap        Wrap and monitor an MCP server command with security boundaries
  logs        View flight recorder audit trail of tool calls and policy blocks
  stats       Print session metrics, policy violations, and token estimates
  help        Help about any command
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
