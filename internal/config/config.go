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
}

type SettingsConfig struct {
	DryRun   bool   `yaml:"dry_run"`
	LogLevel string `yaml:"log_level"`
}

type ToolsConfig struct {
	Allowed []string `yaml:"allowed"`
	Denied  []string `yaml:"denied"`
}

type FilesystemConfig struct {
	Enabled      bool     `yaml:"enabled"`
	AllowedRoots []string `yaml:"allowed_roots"`
	DeniedPaths  []string `yaml:"denied_paths"`
}

type CommandsConfig struct {
	Enabled        bool     `yaml:"enabled"`
	DeniedPatterns []string `yaml:"denied_patterns"`
}

type LimitsConfig struct {
	MaxToolCallsPerMinute   int   `yaml:"max_tool_calls_per_minute"`
	MaxTotalCallsPerSession int   `yaml:"max_total_calls_per_session"`
	MaxSessionTokens        int64 `yaml:"max_session_tokens"`
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

# Outbound Secret Scrubber (Response Filter)
scrubber:
  enabled: true
  redact_patterns: true
  redact_entropy: true
  custom_patterns: []
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
