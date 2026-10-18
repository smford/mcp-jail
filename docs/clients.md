# Client Integrations

Connect `mcp-jail` with popular AI coding agents and desktop clients.

---

## 1. Claude Desktop

Edit your Claude Desktop configuration file:
- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "/usr/local/bin/mcp-jail",
      "args": [
        "wrap",
        "--config", "/Users/alice/projects/myapp/.mcp-jail.yaml",
        "--",
        "npx",
        "-y",
        "@modelcontextprotocol/server-filesystem",
        "/Users/alice/projects/myapp"
      ]
    }
  }
}
```

---

## 2. Cursor IDE

In Cursor, edit `~/.cursor/mcp.json` or project-specific `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "terminal": {
      "command": "mcp-jail",
      "args": [
        "wrap",
        "--config", ".mcp-jail.yaml",
        "--",
        "uvx",
        "mcp-server-commands"
      ]
    }
  }
}
```

---

## 3. Claude Code CLI

Add a sandboxed MCP server through the `claude` CLI:

```bash
claude mcp add secure-filesystem -- mcp-jail wrap -- npx -y @modelcontextprotocol/server-filesystem .
```

To verify active MCP servers in Claude Code:
```bash
claude mcp list
```

---

## 4. Google Antigravity

In your Antigravity agent configuration file (`mcp_settings.json`):

```json
{
  "servers": {
    "workspace-tools": {
      "command": "mcp-jail",
      "args": [
        "wrap",
        "--config", ".mcp-jail.yaml",
        "--",
        "node",
        "./dist/index.js"
      ]
    }
  }
}
```

---

## 5. OpenCode / Generic CLI Subprocess

For any agent that executes an MCP command via standard process spawning:

```bash
mcp-jail wrap [jail-flags] -- <original-mcp-server-command> [args...]
```

`mcp-jail` guarantees transparent stdio pass-through, preserving JSON-RPC 2.0 framing and exit codes.
