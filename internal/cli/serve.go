package cli

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/smford/mcp-jail/internal/recorder"
	"github.com/spf13/cobra"
)

var (
	serveAddr string
	serveDB   string
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Run HTTP daemon for health checks and metrics",
	Long:  "Runs a lightweight HTTP server exposing /healthz and /stats endpoints for container health probes and DAST scanners.",
	RunE: func(cmd *cobra.Command, args []string) error {
		mux := http.NewServeMux()
		mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		})

		mux.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
			rec, err := recorder.NewRecorder(serveDB)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			defer rec.Close()

			stats, err := rec.GetStats("")
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			_ = json.NewEncoder(w).Encode(stats)
		})

		fmt.Fprintf(os.Stderr, "mcp-jail daemon listening on %s\n", serveAddr)
		return http.ListenAndServe(serveAddr, mux)
	},
}

func init() {
	serveCmd.Flags().StringVar(&serveAddr, "addr", ":8080", "HTTP listen address")
	serveCmd.Flags().StringVar(&serveDB, "db", "~/.mcp-jail/flight-recorder.db", "Path to SQLite flight recorder database")
}
