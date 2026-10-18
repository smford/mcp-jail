package cli

import (
	"fmt"
	"os"

	"github.com/smford/mcp-jail/internal/config"
	"github.com/spf13/cobra"
)

var initForce bool

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Generate default .mcp-jail.yaml security policy configuration",
	Long:  "Generates a sensible default .mcp-jail.yaml policy file in the current working directory with strict boundary protection.",
	RunE: func(cmd *cobra.Command, args []string) error {
		target := ".mcp-jail.yaml"
		if _, err := os.Stat(target); err == nil && !initForce {
			return fmt.Errorf("%s already exists. Use --force to overwrite", target)
		}

		yamlContent := config.DefaultConfigYAML()
		if err := os.WriteFile(target, []byte(yamlContent), 0644); err != nil {
			return fmt.Errorf("failed to write %s: %w", target, err)
		}

		fmt.Printf("Created %s with strict security boundaries:\n", target)
		fmt.Println("  - Allowed roots: Current workspace (.)")
		fmt.Println("  - Denied paths:  ~/.ssh, ~/.aws, ~/.kube, /etc, **/.env*")
		fmt.Println("  - Command guard: Blocked destructive commands (rm -rf, git push --force, etc.)")
		fmt.Println("  - Scrubber:      Auto-redaction of AWS keys, GitHub PATs, private keys")
		return nil
	},
}

func init() {
	initCmd.Flags().BoolVarP(&initForce, "force", "f", false, "Overwrite existing configuration file")
}
