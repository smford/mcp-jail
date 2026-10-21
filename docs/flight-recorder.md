# SQLite Flight Recorder & Audit Trail

The SQLite Flight Recorder provides persistent, queryable compliance and security auditing for all MCP interactions.

---

## Performance & Architecture

- **Sub-millisecond Stdio Latency**: Stdio messages are pushed directly into a 10,000-element buffered Go channel worker. Database I/O runs asynchronously in a dedicated background goroutine.
- **Pure-Go SQLite Engine**: Uses `modernc.org/sqlite` with zero CGO dependencies.
- **WAL Mode**: Operates in SQLite Write-Ahead Logging (`PRAGMA journal_mode = WAL;`) with a 5000ms busy timeout for concurrent query access while sessions are running.
- **Redaction-Safe Storage**: Payloads are stored in their scrubbed form so the flight recorder database itself never leaks credentials.

---

## Database Schema

```mermaid
erDiagram
    SESSIONS ||--o{ EVENTS : contains
    SESSIONS {
        string id PK
        datetime started_at
        datetime ended_at
        string command
        string cwd
        int total_calls
        int blocked_calls
        int redacted_secrets
        int est_tokens
    }
    EVENTS {
        int id PK
        string session_id FK
        datetime timestamp
        string direction
        string rpc_id
        string method
        string tool_name
        string action
        string rule_triggered
        int latency_ms
        string payload_json
    }
```

---

## Querying Audit Logs

### View Recent Events (`mcp-jail logs`)

```bash
mcp-jail logs
```

Output:

```text
TIMESTAMP     DIR  RPC ID  TOOL/METHOD  ACTION    LATENCY  DETAILS
14:22:01.120  →    2       read_file    ALLOWED   -        {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params":...
14:22:01.124  ←    2       read_file    ALLOWED   4ms      {"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text"...
14:22:05.801  →    3       read_file    BLOCKED   -        Rule: filesystem_boundary
14:22:10.450  →    4       leak_secret  ALLOWED   -        {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params":...
14:22:10.452  ←    4       leak_secret  REDACTED  2ms      Secrets scrubbed from output
```

### Filter by Session ID or Violations

```bash
# Show only policy violations
mcp-jail logs --blocked-only

# Filter for a specific session
mcp-jail logs --session e2e-session-123 --tail 100

# Stream events in real time
mcp-jail logs -f
```

---

## Structured Log Formats (JSON, CEF, logfmt)

`mcp-jail` can output and export logs in three enterprise structured formats:

```bash
# Output as single-line JSON / JSONL
mcp-jail logs --format json

# Output as Common Event Format (CEF) for Splunk / ArcSight / Sentinel
mcp-jail logs --format cef

# Output as logfmt (key=value) for Loki / terminal analysis
mcp-jail logs --format logfmt
```

### Format Examples

#### 1. JSON
```json
{"id":42,"session_id":"sess-123","timestamp":"2026-10-21T00:15:00Z","direction":"host_to_server","rpc_id":"3","method":"tools/call","tool_name":"execute_sql","action":"blocked","rule_triggered":"DROP DATABASE blocked","latency_ms":12}
```

#### 2. CEF (Common Event Format)
```text
CEF:0|smford|mcp-jail|0.5.0|POLICY_VIOLATION|Tool execution blocked by security policy|7|act=blocked tool=execute_sql method=tools/call reason=DROP\ DATABASE\ blocked cs1=sess-123 cs1Label=SessionID cn1=12 cn1Label=LatencyMs cs2=3 cs2Label=RPCID rt=1792541700000
```

#### 3. logfmt
```text
ts=2026-10-21T00:15:00Z level=warn action=blocked session_id=sess-123 tool=execute_sql method=tools/call rule="DROP DATABASE blocked" latency_ms=12 rpc_id=3 direction=host_to_server
```

---

## Continuous Log Export to SIEM

In `.mcp-jail.yaml`, configure the `export` block to continuously append structured records to an external file or SIEM forwarder socket:

```yaml
# Continuous Audit Log Export & SIEM Ingestion
export:
  enabled: true
  file: "/var/log/mcp-jail/audit.log"
  format: "cef" # "json", "cef", or "logfmt"
```

---

## Metrics & Statistics (`mcp-jail stats`)

```bash
mcp-jail stats
```

Output:

```text
====================================================
            MCP-JAIL FLIGHT RECORDER STATS
====================================================
Total Sessions Monitored:   14
Total Tool Calls:           182
Blocked Violations:         7
Redacted Credentials:       12
Estimated Token Usage:      41920 (~163 KB)
----------------------------------------------------
TOP TOOLS INVOKED:
   1. read_file                (94 calls)
   2. list_directory           (42 calls)
   3. execute_command          (31 calls)
   4. git_status               (15 calls)
====================================================
```
