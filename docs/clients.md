# Client Integrations

Connect `mcp-jail` with popular AI coding agents and desktop clients.

---

## Auditing Installed MCP Servers

You can discover and inspect all MCP servers installed across your AI clients at any time:

```bash
# List all configured servers across all clients and check their protection status
mcp-jail list

# Or target a specific client
mcp-jail list antigravity
mcp-jail list claude

# Output structured JSON for automation
mcp-jail list --json
```

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

## 4. Google Antigravity & Gemini (CLI and GUI)

### One-Click Setup
Automatically detect and wrap MCP servers configured across Google Antigravity CLI and Antigravity GUI (Antigravity 2.0 / Antigravity IDE):

```bash
# Wrap all servers in both Antigravity CLI and GUI configurations
mcp-jail install antigravity

# Or target a specific surface:
mcp-jail install antigravity-cli   # Configures ~/.gemini/antigravity-cli/mcp_config.json
mcp-jail install antigravity-gui   # Configures ~/.gemini/config/mcp_config.json
```

*(Aliases `gemini`, `gemini-cli`, and `gemini-gui` are also supported.)*

To restore the original unwrapped configurations:
```bash
mcp-jail uninstall antigravity
```

### Configuration Locations
- **Antigravity CLI**: `~/.gemini/antigravity-cli/mcp_config.json`
- **Antigravity GUI**: `~/.gemini/config/mcp_config.json`

### Manual Setup
In your Antigravity MCP configuration file (`mcp_config.json`):

```json
{
  "mcpServers": {
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

> **Note**: Remote MCP servers configured with `serverUrl` or `url` (such as Home Assistant) are automatically detected and safely skipped without modification.

---

## 5. OpenCode / Generic CLI Subprocess

For any agent that executes an MCP command via standard process spawning:

```bash
mcp-jail wrap [jail-flags] -- <original-mcp-server-command> [args...]
```

`mcp-jail` guarantees transparent stdio pass-through, preserving JSON-RPC 2.0 framing and exit codes.
