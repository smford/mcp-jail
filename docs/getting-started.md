# Getting Started with mcp-jail

Get up and running with `mcp-jail` in under two minutes.

---

## 1. Installation

### Homebrew (macOS & Linux)
```bash
brew install smford/tap/mcp-jail
```

### Go Install
Install directly to your `$GOPATH/bin`:

```bash
go install github.com/smford/mcp-jail/cmd/mcp-jail@latest
```

### Build from Source
`mcp-jail` is written in 100% pure Go and compiles as a single standalone executable without needing any C compiler, system headers, or external database libraries:

```bash
git clone https://github.com/smford/mcp-jail.git
cd mcp-jail
make build

# The standalone binary is produced at:
./bin/mcp-jail --help
```

Verify your installation:

```bash
mcp-jail --help
```

---

## 2. Initialize Policy Configuration

Run `mcp-jail init` inside your project root to generate a sensible default `.mcp-jail.yaml`:

```bash
mcp-jail init
```

Output:
```
Created .mcp-jail.yaml with strict security boundaries:
  - Allowed roots: Current workspace (.)
  - Denied paths:  ~/.ssh, ~/.aws, ~/.kube, /etc, **/.env*
  - Command guard: Blocked destructive commands (rm -rf, git push --force, etc.)
  - Scrubber:      Auto-redaction of AWS keys, GitHub PATs, private keys
```

> [!NOTE]
> If `.mcp-jail.yaml` already exists, `mcp-jail init` prevents accidental overwrites. Pass `--force` to regenerate.

---

## 3. Wrap Your First MCP Server

Prepend `mcp-jail wrap --` to your existing MCP server invocation:

```bash
mcp-jail wrap -- npx -y @modelcontextprotocol/server-filesystem .
```

You can pass configuration flags before the `--` separator:

```bash
mcp-jail wrap \
  --config .mcp-jail.yaml \
  --db ~/.mcp-jail/flight-recorder.db \
  --session-id my-work-session \
  -- \
  npx -y @modelcontextprotocol/server-filesystem .
```

---

## 4. Verify Policy Enforcement

When an AI coding agent attempts to access restricted paths (such as `~/.ssh/id_rsa` or `../.env`), `mcp-jail` intercepts the tool call and immediately returns a graceful error:

```json
{
  "jsonrpc": "2.0",
  "id": 4,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "[MCP-JAIL POLICY BLOCK] Tool execution denied by local firewall.\nRule violated: filesystem_boundary\nReason: Access to path \"../.env\" is denied by pattern \"**/.env*\"\nAction required: Do not attempt to bypass this restriction. Inform the user or choose a safe alternative."
      }
    ],
    "isError": true
  }
}
```

The AI agent reads this rationale and self-corrects without crashing or disconnecting from the MCP server.

---

## 5. Review the Audit Log

In another terminal window, inspect the SQLite flight recorder:

```bash
# View recent events
mcp-jail logs

# View only blocked violations
mcp-jail logs --blocked-only

# View high-level session statistics
mcp-jail stats
```

---

## Next Steps

- Explore [Architecture](architecture.md) to understand how stdio proxying works.
- Configure custom boundaries in [Policy Engine](policy-engine.md).
- Connect your AI client in [Client Integrations](clients.md).
