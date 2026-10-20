package cli

import (
	"fmt"
	"os"

	"github.com/smford/mcp-jail/internal/config"
	"github.com/spf13/cobra"
)

var (
	initForce       bool
	initPreset      string
	initListPresets bool
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Generate .mcp-jail.yaml security policy configuration",
	Long: `Generates a sensible .mcp-jail.yaml policy file in the current working directory.
Supports tailored policy presets for coding assistants, databases, GitHub, Home Assistant, and minimal setups.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		out := cmd.OutOrStdout()

		if initListPresets {
			fmt.Fprintln(out, "Available security presets:")
			for _, p := range config.ListPresets() {
				fmt.Fprintf(out, "  %-14s %s\n", p.Name, p.Description)
				for _, s := range p.Summary {
					fmt.Fprintf(out, "    • %s\n", s)
				}
			}
			return nil
		}

		p, err := config.GetPreset(initPreset)
		if err != nil {
			return err
		}

		target := ".mcp-jail.yaml"
		if _, err := os.Stat(target); err == nil && !initForce {
			return fmt.Errorf("%s already exists. Use --force to overwrite", target)
		}

		if err := os.WriteFile(target, []byte(p.YAML), 0644); err != nil {
			return fmt.Errorf("failed to write %s: %w", target, err)
		}

		fmt.Fprintf(out, "Created %s using preset [%s]:\n", target, p.Name)
		for _, s := range p.Summary {
			fmt.Fprintf(out, "  - %s\n", s)
		}
		return nil
	},
}

func init() {
	initCmd.Flags().BoolVarP(&initForce, "force", "f", false, "Overwrite existing configuration file")
	initCmd.Flags().StringVarP(&initPreset, "preset", "p", "default", "Policy preset template (coding, database, github, homeassistant, minimal, default)")
	initCmd.Flags().BoolVar(&initListPresets, "list-presets", false, "List available presets and their descriptions")
}
