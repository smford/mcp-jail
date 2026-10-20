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

Run `mcp-jail init` inside your project root to generate a `.mcp-jail.yaml` policy file. You can choose a tailored preset for your server workload (`coding`, `database`, `github`, `homeassistant`, `minimal`, or `default`):

```bash
# List available security presets
mcp-jail init --list-presets

# Initialize with a preset tailored to your tools
mcp-jail init --preset coding
```

Output:
```
Created .mcp-jail.yaml using preset [coding]:
  - Allowed roots: Current project workspace (.)
  - Denied paths: ~/.ssh, ~/.aws, ~/.gnupg, ~/.kube, ~/.netrc, /etc, **/.env*
  - Command guard: Blocks 'rm -rf /', 'git push --force', 'npm publish --force', 'curl | sh'
  - Args rules: Prevents pushing directly to main/master branches
  - Scrubber: Strips API keys, cloud credentials, and private keys from prompts & outputs
```

> [!NOTE]
> If `.mcp-jail.yaml` already exists, `mcp-jail init` prevents accidental overwrites. Pass `--force` to regenerate.

---

## 3. Verify Environment Health

Run `mcp-jail doctor` to check client configurations, verify reachability of servers, audit policy syntax, and check sandbox readiness:

```bash
mcp-jail doctor
```

---

## 4. Wrap Your First MCP Server

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

## 5. Verify Policy Enforcement

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

## 6. Review Audit Logs & Replay Sessions

In another terminal window, inspect the SQLite flight recorder or stream events live:

```bash
# Stream audit logs live in real time
mcp-jail logs -f

# View recent blocked policy violations
mcp-jail logs --blocked-only

# View high-level session statistics
mcp-jail stats

# Deterministically replay recorded sessions for testing
mcp-jail replay --list
mcp-jail replay <session-id>
```

---

## Next Steps

- Explore [Architecture](architecture.md) to understand how stdio proxying works.
- Configure custom boundaries in [Policy Engine](policy-engine.md).
- Connect your AI client in [Client Integrations](clients.md).
