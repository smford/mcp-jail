package config

import (
	"fmt"
	"sort"
	"strings"
)

// Preset represents a pre-configured security policy template.
type Preset struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Summary     []string `json:"summary"`
	YAML        string   `json:"yaml"`
}

var presets = map[string]*Preset{
	"default": {
		Name:        "default",
		Description: "General-purpose balanced security policy for AI developer assistants",
		Summary: []string{
			"Allowed roots: Current workspace (.)",
			"Denied paths: ~/.ssh, ~/.aws, ~/.kube, /etc, **/.env*",
			"Command guard: Blocked destructive commands (rm -rf, git push --force, terraform destroy)",
			"Scrubber: Auto-redaction of AWS keys, GitHub PATs, private keys, Slack tokens",
		},
		YAML: DefaultConfigYAML(),
	},
	"coding": {
		Name:        "coding",
		Description: "Optimized for code generation & dev agents (Cursor, Claude Code, Antigravity, VS Code)",
		Summary: []string{
			"Allowed roots: Current project workspace (.)",
			"Denied paths: ~/.ssh, ~/.aws, ~/.gnupg, ~/.kube, ~/.netrc, /etc, **/.env*",
			"Command guard: Blocks 'rm -rf /', 'git push --force', 'npm publish --force', 'curl | sh'",
			"Args rules: Prevents pushing directly to main/master branches",
			"Scrubber: Strips API keys, cloud credentials, and private keys from prompts & outputs",
		},
		YAML: `# .mcp-jail.yaml - Preset: coding
# Designed for developer assistants (Cursor, Claude Code, Antigravity, Roo Code)
version: "1"

settings:
  dry_run: false
  log_level: "info"

tools:
  allowed: []
  denied:
    - "^format_disk$"
    - "^delete_repo$"
    - "^publish_package$"
  args_rules:
    - tool: "git_push"
      arg: "branch"
      denied_patterns:
        - "^main$"
        - "^master$"
        - "^release/.*"

filesystem:
  enabled: true
  allowed_roots:
    - "."
  denied_paths:
    - "**/.env*"
    - "~/.ssh/**"
    - "~/.aws/**"
    - "~/.gnupg/**"
    - "~/.kube/**"
    - "~/.netrc"
    - "/etc/**"

command_guard:
  enabled: true
  denied_patterns:
    - 'rm\s+(-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r)\s+/'
    - 'rm\s+(-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r)\s+~'
    - 'curl\s+.*\|\s*(ba)?sh'
    - 'wget\s+.*\|\s*(ba)?sh'
    - 'git\s+push\s+.*(--force|-f)'
    - 'npm\s+publish\s+--force'

scrubber:
  enabled: true
  block_on_detection: false
`,
	},
	"database": {
		Name:        "database",
		Description: "Protects SQL and data analytics MCP servers against schema drops and data leaks",
		Summary: []string{
			"Args rules: Blocks unconstrained DROP TABLE/DATABASE, TRUNCATE, and unqualified DELETE",
			"Tool filters: Denies admin and schema destruction tools",
			"Rate limits: 60 queries/min cap, 50,000 token output ceiling to prevent bulk exfiltration",
			"Scrubber: Redacts database passwords, connection strings, and cloud credentials",
		},
		YAML: `# .mcp-jail.yaml - Preset: database
# Designed for database MCP servers (PostgreSQL, MySQL, SQLite, Supabase, BigQuery, Snowflake)
version: "1"

settings:
  dry_run: false
  log_level: "info"

tools:
  allowed: []
  denied:
    - ".*drop_table.*"
    - ".*drop_database.*"
    - ".*admin_execute.*"
  args_rules:
    - tool: "execute_sql"
      arg: "query"
      denied_patterns:
        - "(?i)DROP\\s+(DATABASE|SCHEMA|TABLE)"
        - "(?i)TRUNCATE\\s+TABLE"
        - "(?i)ALTER\\s+TABLE.*DROP"
        - "(?i)GRANT\\s+ALL"
        - "(?i)DELETE\\s+FROM\\s+\\w+\\s*(;|$)"
    - tool: "query"
      arg: "sql"
      denied_patterns:
        - "(?i)DROP\\s+(DATABASE|SCHEMA|TABLE)"
        - "(?i)TRUNCATE\\s+TABLE"

filesystem:
  enabled: false

rate_limit:
  enabled: true
  max_calls_per_minute: 60
  token_budget_per_session: 50000

scrubber:
  enabled: true
  block_on_detection: false
  denied_patterns:
    - 'postgres://[a-zA-Z0-9_]+:[^@]+@'
    - 'mysql://[a-zA-Z0-9_]+:[^@]+@'
    - 'mongodb(\\+srv)?://[a-zA-Z0-9_]+:[^@]+@'
`,
	},
	"github": {
		Name:        "github",
		Description: "Secures Git and GitHub MCP servers against destructive repository actions",
		Summary: []string{
			"Args rules: Prevents force pushes and direct commits to main/master branches",
			"Tool filters: Denies repository deletion, secret access, and dismissal of reviews",
			"Command guard: Rejects force pushing, rebasing upstream main, and hard resets",
			"Scrubber: Redacts GitHub Classic and Fine-grained Personal Access Tokens (ghp_, github_pat_)",
		},
		YAML: `# .mcp-jail.yaml - Preset: github
# Designed for GitHub, GitLab, and Git CLI MCP servers
version: "1"

settings:
  dry_run: false
  log_level: "info"

tools:
  allowed: []
  denied:
    - "^delete_repository$"
    - "^delete_repo$"
    - "^delete_branch$"
    - "^dismiss_review$"
    - ".*secret.*"
  args_rules:
    - tool: "push_files"
      arg: "branch"
      denied_patterns:
        - "^main$"
        - "^master$"
    - tool: "create_pull_request"
      arg: "base"
      denied_patterns:
        - "^production$"

command_guard:
  enabled: true
  denied_patterns:
    - 'git\s+push\s+.*(--force|-f)'
    - 'git\s+reset\s+--hard'
    - 'git\s+clean\s+-[a-zA-Z]*f'

scrubber:
  enabled: true
  block_on_detection: true
  denied_patterns:
    - 'ghp_[A-Za-z0-9_]{36,}'
    - 'github_pat_[A-Za-z0-9_]{82}'
`,
	},
	"homeassistant": {
		Name:        "homeassistant",
		Description: "Protects smart home environments (Home Assistant MCP) from unsafe device actuation",
		Summary: []string{
			"Args rules: Bounds climate thermostat target temperature between 16°C and 26°C",
			"Tool filters: Blocks physical entry points (locks, alarm control panels, garage doors)",
			"Rate limits: 30 calls/min to prevent rapid toggle loops",
		},
		YAML: `# .mcp-jail.yaml - Preset: homeassistant
# Designed for IoT & Home Assistant MCP servers
version: "1"

settings:
  dry_run: false
  log_level: "info"

tools:
  allowed:
    - "^HassTurnOn$"
    - "^HassTurnOff$"
    - "^HassLightSet$"
    - "^HassClimateSetTemperature$"
    - "^HassMedia.*$"
    - "^HassList.*$"
    - "^Get.*$"
    - "^todo_.*$"
  denied:
    # Deny physical access control tools and sirens
    - ".*lock.*"
    - ".*alarm.*"
    - ".*garage.*"
    - ".*siren.*"
  args_rules:
    # Restrict climate thermostat target temperature to a safe comfort range
    - tool: "HassClimateSetTemperature"
      arg: "temperature"
      numeric_range:
        min: 16.0
        max: 26.0

rate_limit:
  enabled: true
  max_calls_per_minute: 30
`,
	},
	"minimal": {
		Name:        "minimal",
		Description: "Lightweight baseline policy with minimal constraints for quick testing",
		Summary: []string{
			"Allowed roots: Workspace directory (.)",
			"Denied paths: Standard sensitive files (~/.ssh, ~/.aws, .env)",
			"Tools: All permitted without restriction",
		},
		YAML: `# .mcp-jail.yaml - Preset: minimal
# Lightweight baseline for testing and development
version: "1"

settings:
  dry_run: false
  log_level: "info"

filesystem:
  enabled: true
  allowed_roots:
    - "."
  denied_paths:
    - "**/.env*"
    - "~/.ssh/**"
    - "~/.aws/**"

scrubber:
  enabled: true
  block_on_detection: false
`,
	},
}

// GetPreset returns the preset with the given name, or an error if not found.
func GetPreset(name string) (*Preset, error) {
	key := strings.ToLower(strings.TrimSpace(name))
	if p, ok := presets[key]; ok {
		return p, nil
	}
	available := ListPresetNames()
	return nil, fmt.Errorf("unknown preset %q. Available presets: %s", name, strings.Join(available, ", "))
}

// ListPresets returns all available presets sorted by name.
func ListPresets() []*Preset {
	keys := make([]string, 0, len(presets))
	for k := range presets {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	res := make([]*Preset, 0, len(keys))
	for _, k := range keys {
		res = append(res, presets[k])
	}
	return res
}

// ListPresetNames returns the sorted names of all available presets.
func ListPresetNames() []string {
	keys := make([]string, 0, len(presets))
	for k := range presets {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
