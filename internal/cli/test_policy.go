package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/smford/mcp-jail/internal/config"
	"github.com/smford/mcp-jail/internal/policy"
	"github.com/spf13/cobra"
)

var (
	testPolicyConfig   string
	testPolicyTool     string
	testPolicyArgs     string
	testPolicyResource string
	testPolicyPrompt   string
)

var testPolicyCmd = &cobra.Command{
	Use:   "test-policy [flags]",
	Short: "Dry-run and simulate policy evaluation for tools, resources, or prompts",
	Long: `Simulates security policy evaluation without running an active MCP server.
Useful for validating regex patterns, path boundaries, and argument rules.`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg, err := config.LoadConfig(testPolicyConfig)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Config error: %v\n", err)
			os.Exit(1)
		}

		engine, err := policy.NewEngine(cfg, ".")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Policy engine error: %v\n", err)
			os.Exit(1)
		}

		executed := false

		// 1. Tool test
		if testPolicyTool != "" {
			executed = true
			argMap := make(map[string]interface{})
			if testPolicyArgs != "" {
				if err := json.Unmarshal([]byte(testPolicyArgs), &argMap); err != nil {
					fmt.Fprintf(os.Stderr, "Failed to parse --args JSON: %v\n", err)
					os.Exit(1)
				}
			}

			fmt.Printf("Evaluating tool call: %s\n", testPolicyTool)
			if len(argMap) > 0 {
				fmt.Printf("Arguments: %s\n", testPolicyArgs)
			}

			violation := engine.EvaluateToolCall(testPolicyTool, argMap)
			if violation != nil {
				fmt.Printf("\nResult: ❌ BLOCKED\n")
				fmt.Printf("Rule Triggered: %s\n", violation.RuleName)
				fmt.Printf("Reason:         %s\n", violation.Reason)
			} else {
				fmt.Printf("\nResult: ✅ PERMITTED\n")
			}
		}

		// 2. Resource test
		if testPolicyResource != "" {
			executed = true
			fmt.Printf("Evaluating resource URI: %s\n", testPolicyResource)
			violation := engine.EvaluateResource(testPolicyResource)
			if violation != nil {
				fmt.Printf("\nResult: ❌ BLOCKED\n")
				fmt.Printf("Rule Triggered: %s\n", violation.RuleName)
				fmt.Printf("Reason:         %s\n", violation.Reason)
			} else {
				fmt.Printf("\nResult: ✅ PERMITTED\n")
			}
		}

		// 3. Prompt test
		if testPolicyPrompt != "" {
			executed = true
			fmt.Printf("Evaluating prompt name: %s\n", testPolicyPrompt)
			violation := engine.EvaluatePrompt(testPolicyPrompt)
			if violation != nil {
				fmt.Printf("\nResult: ❌ BLOCKED\n")
				fmt.Printf("Rule Triggered: %s\n", violation.RuleName)
				fmt.Printf("Reason:         %s\n", violation.Reason)
			} else {
				fmt.Printf("\nResult: ✅ PERMITTED\n")
			}
		}

		if !executed {
			fmt.Println("No test target specified. Use --tool, --resource, or --prompt to test.")
			fmt.Println("Example: mcp-jail test-policy --tool write_file --args '{\"path\": \"/etc/passwd\"}'")
		}
	},
}

func init() {
	testPolicyCmd.Flags().StringVarP(&testPolicyConfig, "config", "c", "", "Path to .mcp-jail.yaml config")
	testPolicyCmd.Flags().StringVar(&testPolicyTool, "tool", "", "Tool name to test (e.g. bash, write_file)")
	testPolicyCmd.Flags().StringVar(&testPolicyArgs, "args", "", "JSON string of tool arguments (e.g. '{\"command\": \"rm -rf /\"}')")
	testPolicyCmd.Flags().StringVar(&testPolicyResource, "resource", "", "Resource URI to test (e.g. file:///etc/shadow)")
	testPolicyCmd.Flags().StringVar(&testPolicyPrompt, "prompt", "", "Prompt template name to test")
}
