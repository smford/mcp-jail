package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/smford/mcp-jail/internal/config"
	"github.com/smford/mcp-jail/internal/learner"
	"github.com/smford/mcp-jail/internal/proxy"
	"github.com/spf13/cobra"
)

var learnCmd = &cobra.Command{
	Use:   "learn [flags] -- <command> [args...]",
	Short: "Run an MCP server in learning mode to automatically generate a tailored security policy",
	Long: `Execute an MCP server in permissive learning mode.
mcp-jail monitors every tool called, file accessed, and command executed, then synthesizes
a minimal, least-privilege .mcp-jail.learned.yaml policy ready for production use.`,
	DisableFlagParsing: false,
	RunE: func(cmd *cobra.Command, args []string) error {
		cmdArgs := cmd.Flags().Args()
		if len(cmdArgs) == 0 {
			return fmt.Errorf("no target command specified. Usage: mcp-jail learn [flags] -- <command> [args...]")
		}

		configPath, _ := cmd.Flags().GetString("config")
		outputPath, _ := cmd.Flags().GetString("output")
		dbPath, _ := cmd.Flags().GetString("db")

		cfg, err := config.LoadConfig(configPath)
		if err != nil {
			return fmt.Errorf("failed to load configuration: %w", err)
		}

		// Learning mode runs in dry-run mode so all normal calls succeed and are recorded
		cfg.Settings.DryRun = true

		l := learner.NewLearner()

		prx, err := proxy.NewProxy(proxy.Options{
			Config:  cfg,
			Command: cmdArgs[0],
			Args:    cmdArgs[1:],
			DBPath:  dbPath,
			DryRun:  true,
			Learner: l,
		})
		if err != nil {
			return fmt.Errorf("failed to initialize proxy: %w", err)
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
		go func() {
			<-sigChan
			cancel()
		}()

		fmt.Fprintf(os.Stderr, "🎓 [mcp-jail] Learning mode active for: %s\n", cmdArgs[0])
		fmt.Fprintf(os.Stderr, "   Exercising server... policy will be generated when process exits.\n\n")

		exitCode, runErr := prx.Run(ctx)

		// Generate learned policy
		yamlStr, genErr := l.GenerateYAML()
		if genErr != nil {
			return fmt.Errorf("failed to generate learned policy: %w", genErr)
		}

		if err := os.WriteFile(outputPath, []byte(yamlStr), 0644); err != nil {
			return fmt.Errorf("failed to write learned policy to %s: %w", outputPath, err)
		}

		fmt.Fprintf(os.Stderr, "\n✨ [mcp-jail] Policy generation complete!\n")
		fmt.Fprintf(os.Stderr, "   Generated least-privilege policy saved to: \033[1;32m%s\033[0m\n", outputPath)
		fmt.Fprintf(os.Stderr, "   To use it: mv %s .mcp-jail.yaml\n", outputPath)

		if runErr != nil {
			return runErr
		}
		if exitCode != 0 {
			os.Exit(exitCode)
		}
		return nil
	},
}

func init() {
	learnCmd.Flags().StringP("config", "c", "", "Base policy configuration file to augment")
	learnCmd.Flags().StringP("output", "o", ".mcp-jail.learned.yaml", "Output path for the generated policy YAML")
	learnCmd.Flags().String("db", "", "Path to SQLite flight recorder database")
}
