package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Config represents the top-level mcp-jail configuration.
type Config struct {
	Version    string           `yaml:"version"`
	Settings   SettingsConfig   `yaml:"settings"`
	Tools      ToolsConfig      `yaml:"tools"`
	Filesystem FilesystemConfig `yaml:"filesystem"`
	Commands   CommandsConfig   `yaml:"commands"`
	Limits     LimitsConfig     `yaml:"limits"`
	Scrubber   ScrubberConfig   `yaml:"scrubber"`
	Approval   ApprovalConfig   `yaml:"approval"`
	Vault      VaultConfig      `yaml:"vault"`
	Sampling   SamplingConfig   `yaml:"sampling"`
	Snapshots  SnapshotsConfig  `yaml:"snapshots"`
	Export     ExportConfig     `yaml:"export"`
	Resources  ResourcesConfig  `yaml:"resources"`
	Prompts    PromptsConfig    `yaml:"prompts"`
	Sandbox    SandboxConfig    `yaml:"sandbox"`
	Alerts     AlertsConfig     `yaml:"alerts"`
}

type SettingsConfig struct {
	DryRun   bool   `yaml:"dry_run"`
	LogLevel string `yaml:"log_level"`
}

type ToolsConfig struct {
	Allowed []string      `yaml:"allowed"`
	Denied  []string      `yaml:"denied"`
	Ask     []string      `yaml:"ask"`
	Rules   []ToolArgRule `yaml:"rules,omitempty"`
}

// ToolArgRule defines fine-grained argument constraints for matching tools.
type ToolArgRule struct {
	Tool      string                  `yaml:"tool"`                 // Regex pattern for matching tool name
	DenyArgs  map[string]string       `yaml:"deny_args,omitempty"`  // Argument name -> regex pattern to deny
	AllowArgs map[string]string       `yaml:"allow_args,omitempty"` // Argument name -> regex pattern that must match
	Range     map[string]NumericRange `yaml:"range,omitempty"`      // Argument name -> min/max numeric constraints
	Reason    string                  `yaml:"reason,omitempty"`     // Custom refusal message
}

// NumericRange defines optional minimum and maximum bounds for a numeric parameter.
type NumericRange struct {
	Min *float64 `yaml:"min,omitempty"`
	Max *float64 `yaml:"max,omitempty"`
}

type FilesystemConfig struct {
	Enabled      bool     `yaml:"enabled"`
	AllowedRoots []string `yaml:"allowed_roots"`
	DeniedPaths  []string `yaml:"denied_paths"`
}

type CommandsConfig struct {
	Enabled        bool     `yaml:"enabled"`
	DeniedPatterns []string `yaml:"denied_patterns"`
	AskPatterns    []string `yaml:"ask_patterns"`
}

type LimitsConfig struct {
	MaxToolCallsPerMinute   int                   `yaml:"max_tool_calls_per_minute"`
	MaxTotalCallsPerSession int                   `yaml:"max_total_calls_per_session"`
	MaxSessionTokens        int64                 `yaml:"max_session_tokens"`
	ToolLimits              []ToolRateLimitConfig `yaml:"tool_limits"`
}

// ToolRateLimitConfig configures fine-grained sliding-window limits for a specific tool.
type ToolRateLimitConfig struct {
	Tool         string `yaml:"tool"`
	MaxPerMinute int    `yaml:"max_per_minute"`
	MaxPerHour   int    `yaml:"max_per_hour"`
}

type ScrubberConfig struct {
	Enabled        bool            `yaml:"enabled"`
	RedactPatterns bool            `yaml:"redact_patterns"`
	RedactEntropy  bool            `yaml:"redact_entropy"`
	CustomPatterns []CustomPattern `yaml:"custom_patterns"`
}

type CustomPattern struct {
	Name  string `yaml:"name"`
	Regex string `yaml:"regex"`
}

// ApprovalConfig configures Human-in-the-Loop interactive approvals.
type ApprovalConfig struct {
	Enabled        bool     `yaml:"enabled"`
	TimeoutSec     int      `yaml:"timeout_sec"`
	NonInteractive bool     `yaml:"non_interactive"`
	AskTools       []string `yaml:"ask_tools"`
	AskCommands    []string `yaml:"ask_commands"`
}

// VaultConfig configures two-way ephemeral secret tokenization.
type VaultConfig struct {
	Enabled bool `yaml:"enabled"`
}

// SamplingConfig configures prompt injection checks on MCP sampling requests.
type SamplingConfig struct {
	Enabled         bool `yaml:"enabled"`
	BlockInjections bool `yaml:"block_injections"`
}

// SnapshotsConfig configures file modification snapshots for diff & rollback.
type SnapshotsConfig struct {
	Enabled       bool `yaml:"enabled"`
	MaxFileSizeKB int  `yaml:"max_file_size_kb"`
}

// ExportConfig configures audit event streaming and SIEM export.
type ExportConfig struct {
	Enabled bool   `yaml:"enabled"`
	File    string `yaml:"file"`
}

// ResourcesConfig configures access rules for MCP resources/read and resources/subscribe.
type ResourcesConfig struct {
	Enabled     bool     `yaml:"enabled"`
	AllowedURIs []string `yaml:"allowed_uris"`
	DeniedURIs  []string `yaml:"denied_uris"`
}

// PromptsConfig configures access rules for MCP prompts/get.
type PromptsConfig struct {
	Enabled bool     `yaml:"enabled"`
	Allowed []string `yaml:"allowed"`
	Denied  []string `yaml:"denied"`
}

// SandboxConfig configures OS-level subprocess sandboxing (e.g. bwrap or sandbox-exec).
type SandboxConfig struct {
	Enabled        bool `yaml:"enabled"`
	IsolateNetwork bool `yaml:"isolate_network"`
	ReadOnlyRoot   bool `yaml:"read_only_root"`
}

// AlertsConfig configures real-time webhook notifications for security events.
type AlertsConfig struct {
	Enabled    bool     `yaml:"enabled"`
	WebhookURL string   `yaml:"webhook_url"`
	Events     []string `yaml:"events"`
}

// DefaultConfig returns the default strict configuration.
func DefaultConfig() *Config {
	return &Config{
		Version: "1",
		Settings: SettingsConfig{
			DryRun:   false,
			LogLevel: "info",
		},
		Tools: ToolsConfig{
			Allowed: []string{},
			Denied: []string{
				"^format_disk$",
				"^drop_database$",
			},
		},
		Filesystem: FilesystemConfig{
			Enabled: true,
			AllowedRoots: []string{
				".",
			},
			DeniedPaths: []string{
				"**/.env*",
				"~/.ssh/**",
				"~/.aws/**",
				"~/.kube/**",
				"/etc/**",
				"/var/run/**",
				"~/.gnupg/**",
				"**/*id_rsa*",
				"**/*id_ed25519*",
				"**/*.pem",
				"**/*.key",
			},
		},
		Commands: CommandsConfig{
			Enabled: true,
			DeniedPatterns: []string{
				`rm\s+(-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r)\s+.*`,
				`rm\s+-rf\s+.*`,
				`curl\s+.*\|\s*(ba)?sh`,
				`wget\s+.*\|\s*(ba)?sh`,
				`git\s+push\s+.*--force`,
				`aws\s+iam\s+.*`,
				`terraform\s+destroy`,
				`mkfs\..*`,
				`dd\s+if=.*`,
				`:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;`,
				`chmod\s+(-R\s+)?777\s+/`,
			},
		},
		Limits: LimitsConfig{
			MaxToolCallsPerMinute:   60,
			MaxTotalCallsPerSession: 100,
			MaxSessionTokens:        500000,
		},
		Scrubber: ScrubberConfig{
			Enabled:        true,
			RedactPatterns: true,
			RedactEntropy:  true,
			CustomPatterns: []CustomPattern{},
		},
		Approval: ApprovalConfig{
			Enabled:        false,
			TimeoutSec:     30,
			NonInteractive: false,
			AskTools:       []string{},
			AskCommands:    []string{},
		},
		Vault: VaultConfig{
			Enabled: true,
		},
		Sampling: SamplingConfig{
			Enabled:         true,
			BlockInjections: true,
		},
		Snapshots: SnapshotsConfig{
			Enabled:       true,
			MaxFileSizeKB: 512,
		},
		Export: ExportConfig{
			Enabled: false,
			File:    "",
		},
		Resources: ResourcesConfig{
			Enabled:     true,
			AllowedURIs: []string{},
			DeniedURIs: []string{
				"file:///etc/**",
				"**/.env*",
				"**/*id_rsa*",
			},
		},
		Prompts: PromptsConfig{
			Enabled: true,
			Allowed: []string{},
			Denied:  []string{},
		},
		Sandbox: SandboxConfig{
			Enabled:        false,
			IsolateNetwork: false,
			ReadOnlyRoot:   false,
		},
		Alerts: AlertsConfig{
			Enabled:    false,
			WebhookURL: "",
			Events: []string{
				"policy_violation",
				"approval_denied",
				"prompt_injection_detected",
				"rate_limit_exceeded",
			},
		},
	}
}

// DefaultConfigYAML returns the commented YAML string used for `mcp-jail init`.
func DefaultConfigYAML() string {
	return `# .mcp-jail.yaml - Policy configuration for mcp-jail
version: "1"

settings:
  # When dry_run is true, policy violations are logged in the flight recorder but not blocked
  dry_run: false
  log_level: "info"

# Tool Allow/Deny List
tools:
  # If allowed is non-empty, only tool names matching these regexes are permitted
  allowed: []
  # Tool names matching these regexes are always blocked
  denied:
    - "^format_disk$"
    - "^drop_database$"

# Filesystem Boundary Enforcement
filesystem:
  enabled: true
  # allowed_roots: relative paths are resolved against the working directory
  # If non-empty, paths outside allowed roots are blocked
  allowed_roots:
    - "."
  # Denied path globs (supports recursive ** globbing and ~ home directory)
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

# Command Argument Guard (for shell/exec tools)
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
    - ':\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;'
    - 'chmod\s+(-R\s+)?777\s+/'

# Rate & Budget Limiter
limits:
  max_tool_calls_per_minute: 60
  max_total_calls_per_session: 100
  max_session_tokens: 500000
  # Fine-grained limits per tool (sliding window)
  tool_limits: []
  # - tool: "execute_sql"
  #   max_per_minute: 5
  #   max_per_hour: 20

# Outbound Secret Scrubber (Response Filter)
scrubber:
  enabled: true
  redact_patterns: true
  redact_entropy: true
  custom_patterns: []

# Human-in-the-Loop Interactive Approval
approval:
  enabled: false
  timeout_sec: 30
  non_interactive: false
  # Specific tool regex patterns requiring interactive confirmation
  ask_tools: []
  # Specific command regex patterns requiring interactive confirmation
  ask_commands: []

# Two-Way Ephemeral Secret Vault (Reversible Tokenization)
vault:
  enabled: true

# Inbound Prompt Injection & Sampling Guard
sampling:
  enabled: true
  block_injections: true

# File Modification Snapshots (for diff & rollback)
snapshots:
  enabled: true
  max_file_size_kb: 512

# Audit Event Stream & SIEM Export
export:
  enabled: false
  file: ""

# MCP Resources Access Control (resources/read, resources/subscribe)
resources:
  enabled: true
  allowed_uris: []
  denied_uris:
    - "file:///etc/**"
    - "**/.env*"
    - "**/*id_rsa*"

# MCP Prompts Access Control (prompts/get)
prompts:
  enabled: true
  allowed: []
  denied: []

# OS-Level Subprocess Sandboxing (macOS sandbox-exec, Linux bwrap)
sandbox:
  enabled: false
  isolate_network: false
  read_only_root: false

# Real-Time Security Alerts (Webhooks for Slack/Discord/SIEM)
alerts:
  enabled: false
  webhook_url: ""
  events:
    - "policy_violation"
    - "approval_denied"
    - "prompt_injection_detected"
    - "rate_limit_exceeded"
`
}

// LoadConfig loads the configuration from a YAML file.
// If path is empty, it looks for .mcp-jail.yaml in the current directory.
// If the file does not exist and path was empty, DefaultConfig() is returned.
func LoadConfig(path string) (*Config, error) {
	cfg := DefaultConfig()

	if path == "" {
		candidates := []string{
			".mcp-jail.yaml",
			".mcp-jail.yml",
		}
		for _, c := range candidates {
			if _, err := os.Stat(c); err == nil {
				path = c
				break
			}
		}
	}

	if path == "" {
		// No config found, return default
		return cfg, nil
	}

	cleanPath := filepath.Clean(path)
	data, err := os.ReadFile(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %s: %w", cleanPath, err)
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file %s: %w", cleanPath, err)
	}

	return cfg, nil
}
