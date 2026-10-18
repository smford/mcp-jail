package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/smford/mcp-jail/internal/config"
	"github.com/spf13/cobra"
)

var lintPolicyConfig string

type lintIssue struct {
	Level   string // "WARN" or "ERROR"
	Section string
	Message string
}

var lintPolicyCmd = &cobra.Command{
	Use:   "lint-policy [file]",
	Short: "Audit a security policy YAML file for dangerous patterns and misconfigurations",
	Long: `Statically inspects an mcp-jail configuration file to identify overly permissive rules,
unbounded filesystem roots, disabled security features, and potential evasion vectors.`,
	Run: func(cmd *cobra.Command, args []string) {
		path := lintPolicyConfig
		if len(args) > 0 {
			path = args[0]
		}

		cfg, err := config.LoadConfig(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to load policy: %v\n", err)
			os.Exit(1)
		}

		var issues []lintIssue

		// 1. Filesystem audits
		if cfg.Filesystem.Enabled {
			for _, r := range cfg.Filesystem.AllowedRoots {
				cleanR := strings.TrimSpace(r)
				if cleanR == "/" || cleanR == "/usr" || cleanR == "/var" || cleanR == "/etc" || cleanR == "/home" {
					issues = append(issues, lintIssue{
						Level:   "WARN",
						Section: "filesystem.allowed_roots",
						Message: fmt.Sprintf("Allowed root %q exposes entire system partition. Restrict to specific project workspace.", cleanR),
					})
				}
			}
			if len(cfg.Filesystem.AllowedRoots) == 0 {
				issues = append(issues, lintIssue{
					Level:   "WARN",
					Section: "filesystem.allowed_roots",
					Message: "allowed_roots is empty; tool file access is not constrained to workspace roots.",
				})
			}
		} else {
			issues = append(issues, lintIssue{
				Level:   "WARN",
				Section: "filesystem",
				Message: "Filesystem boundary enforcement is disabled.",
			})
		}

		// 2. Tools audits
		for _, a := range cfg.Tools.Allowed {
			if a == ".*" || a == ".+" || a == "*" {
				issues = append(issues, lintIssue{
					Level:   "WARN",
					Section: "tools.allowed",
					Message: "Wildcard pattern in allowed tools allows all tool executions unconditionally.",
				})
			}
		}

		// 3. Security feature checks
		if !cfg.Scrubber.Enabled {
			issues = append(issues, lintIssue{
				Level:   "WARN",
				Section: "scrubber",
				Message: "Secret scrubber is disabled; credentials may leak into AI prompt context.",
			})
		}

		if !cfg.Sampling.Enabled || !cfg.Sampling.BlockInjections {
			issues = append(issues, lintIssue{
				Level:   "WARN",
				Section: "sampling",
				Message: "Prompt injection guard is disabled on sampling messages.",
			})
		}

		if cfg.Approval.Enabled && cfg.Approval.TimeoutSec <= 0 {
			issues = append(issues, lintIssue{
				Level:   "ERROR",
				Section: "approval",
				Message: "Interactive approval enabled with non-positive timeout.",
			})
		}

		// Output results
		if len(issues) == 0 {
			fmt.Println("✅ Policy analysis complete: No security issues detected.")
			return
		}

		fmt.Printf("Policy analysis found %d potential issue(s):\n\n", len(issues))
		hasError := false
		for _, issue := range issues {
			symbol := "⚠️ "
			if issue.Level == "ERROR" {
				symbol = "❌"
				hasError = true
			}
			fmt.Printf("%s [%s] %s: %s\n", symbol, issue.Level, issue.Section, issue.Message)
		}

		if hasError {
			os.Exit(1)
		}
	},
}

func init() {
	lintPolicyCmd.Flags().StringVarP(&lintPolicyConfig, "config", "c", "", "Path to .mcp-jail.yaml config file")
}
