package cli

import (
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/smford/mcp-jail/internal/config"
	"github.com/smford/mcp-jail/internal/httpproxy"
	"github.com/smford/mcp-jail/internal/recorder"
	"github.com/spf13/cobra"
)

var proxyCmd = &cobra.Command{
	Use:   "proxy [flags]",
	Short: "Run an HTTP/SSE reverse proxy securing remote or cloud-hosted MCP servers",
	Long: `Start an HTTP reverse proxy that sits between AI clients and remote MCP servers.
It inspects, enforces security policies, and scrubs secrets on HTTP POST and Server-Sent Events (SSE) streams.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		listenAddr, _ := cmd.Flags().GetString("listen")
		upstreamURL, _ := cmd.Flags().GetString("upstream")
		configPath, _ := cmd.Flags().GetString("config")
		dbPath, _ := cmd.Flags().GetString("db")

		if upstreamURL == "" {
			return fmt.Errorf("--upstream flag is required (e.g. --upstream http://localhost:3000)")
		}

		cfg, err := config.LoadConfig(configPath)
		if err != nil {
			return fmt.Errorf("failed to load configuration: %w", err)
		}

		rec, err := recorder.NewRecorder(dbPath)
		if err != nil {
			return fmt.Errorf("failed to open flight recorder: %w", err)
		}
		defer rec.Close()

		handler, err := httpproxy.NewServer(upstreamURL, cfg, rec)
		if err != nil {
			return fmt.Errorf("failed to initialize http proxy: %w", err)
		}

		server := &http.Server{
			Addr:              listenAddr,
			Handler:           handler,
			ReadHeaderTimeout: 10 * time.Second,
		}

		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
		go func() {
			<-sigChan
			fmt.Println("\nShutting down HTTP proxy server...")
			_ = server.Close()
		}()

		fmt.Printf("🛡️  mcp-jail HTTP/SSE proxy listening on %s -> %s\n", listenAddr, upstreamURL)
		fmt.Printf("   Health check available at http://%s/healthz\n", listenAddr)

		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			return fmt.Errorf("http proxy server error: %w", err)
		}

		return nil
	},
}

func init() {
	proxyCmd.Flags().StringP("listen", "l", ":8080", "Address and port to listen on")
	proxyCmd.Flags().StringP("upstream", "u", "", "URL of upstream remote MCP server (required)")
	proxyCmd.Flags().StringP("config", "c", "", "Path to policy configuration file")
	proxyCmd.Flags().String("db", "", "Path to SQLite flight recorder database")
}
