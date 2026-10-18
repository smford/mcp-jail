package httpproxy

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/smford/mcp-jail/internal/alert"
	"github.com/smford/mcp-jail/internal/config"
	"github.com/smford/mcp-jail/internal/policy"
	"github.com/smford/mcp-jail/internal/proxy"
	"github.com/smford/mcp-jail/internal/ratelimit"
	"github.com/smford/mcp-jail/internal/recorder"
	"github.com/smford/mcp-jail/internal/scrubber"
	"github.com/smford/mcp-jail/internal/vault"
)

// Server is an HTTP/SSE reverse proxy securing remote MCP servers.
type Server struct {
	upstreamURL string
	cfg         *config.Config
	engine      *policy.Engine
	scrubber    *scrubber.Scrubber
	recorder    *recorder.Recorder
	vault       *vault.Vault
	limiter     *ratelimit.Limiter
	alerts      *alert.Dispatcher
	sessionID   string
	httpClient  *http.Client
}

// NewServer constructs an HTTP/SSE MCP proxy server.
func NewServer(upstreamURL string, cfg *config.Config, rec *recorder.Recorder) (*Server, error) {
	eng, err := policy.NewEngine(cfg, ".")
	if err != nil {
		return nil, fmt.Errorf("failed to initialize policy engine: %w", err)
	}

	sc, err := scrubber.NewScrubber(cfg.Scrubber)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize scrubber: %w", err)
	}

	var v *vault.Vault
	if cfg.Vault.Enabled {
		v = vault.NewVault()
	}

	lmt := ratelimit.NewLimiter(cfg.Limits)
	alt := alert.NewDispatcher(cfg.Alerts)

	sessID := uuid.New().String()
	_ = rec.StartSession(&recorder.Session{
		ID:        sessID,
		StartedAt: time.Now(),
		Command:   "http-proxy -> " + upstreamURL,
		Cwd:       ".",
	})

	return &Server{
		upstreamURL: strings.TrimRight(upstreamURL, "/"),
		cfg:         cfg,
		engine:      eng,
		scrubber:    sc,
		recorder:    rec,
		vault:       v,
		limiter:     lmt,
		alerts:      alt,
		sessionID:   sessID,
		httpClient:  &http.Client{Timeout: 60 * time.Second},
	}, nil
}

// ServeHTTP routes incoming requests between SSE streaming and JSON-RPC message handling.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/healthz" {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":     "ok",
			"proxy":      "mcp-jail",
			"session_id": s.sessionID,
		})
		return
	}

	// Handle SSE stream request
	if r.Method == http.MethodGet && (r.URL.Path == "/sse" || strings.Contains(r.Header.Get("Accept"), "text/event-stream")) {
		s.handleSSE(w, r)
		return
	}

	// Handle JSON-RPC POST
	if r.Method == http.MethodPost {
		s.handleJSONRPC(w, r)
		return
	}

	http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
}

func (s *Server) handleSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	upstreamReq, err := http.NewRequestWithContext(r.Context(), http.MethodGet, s.upstreamURL+r.URL.Path, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	upstreamReq.Header.Set("Accept", "text/event-stream")

	resp, err := s.httpClient.Do(upstreamReq)
	if err != nil {
		http.Error(w, fmt.Sprintf("Upstream connection error: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	flusher.Flush()

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Bytes()
		// Scrub outbound secrets from SSE stream
		var scrubbed []byte
		if s.vault != nil {
			scrubbed, _ = s.scrubber.ScrubWithVault(line, s.vault)
		} else {
			scrubbed, _ = s.scrubber.Scrub(line)
		}

		_, _ = w.Write(append(scrubbed, '\n'))
		flusher.Flush()
	}
}

func (s *Server) handleJSONRPC(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}

	// Detokenize with vault
	if s.vault != nil {
		detokenized := s.vault.Detokenize(string(body))
		body = []byte(detokenized)
	}

	msg, err := proxy.ParseMessage(body)
	if err == nil {
		if msg.Method == "tools/call" {
			params, parseErr := msg.ParseToolCallParams()
			if parseErr == nil {
				// Rate limit check
				if s.limiter != nil {
					if limErr := s.limiter.RecordToolCall(params.Name); limErr != nil {
						s.alerts.Dispatch(alert.Event{
							Type:      "rate_limit_exceeded",
							SessionID: s.sessionID,
							Tool:      params.Name,
							Reason:    limErr.Error(),
						})
						ruleName := "rate_limit_exceeded"
						if le, ok := limErr.(*ratelimit.LimitError); ok {
							ruleName = le.RuleName
						}

						s.recorder.RecordEvent(&recorder.Event{
							SessionID:     s.sessionID,
							Timestamp:     time.Now(),
							Direction:     recorder.DirectionHostToServer,
							RPCID:         msg.IDString(),
							Method:        msg.Method,
							ToolName:      params.Name,
							Action:        recorder.ActionBlocked,
							RuleTriggered: ruleName,
							PayloadJSON:   string(body),
						})
						blockedResp, _ := policy.CreateBlockedResponse(msg.ID, ruleName, limErr.Error())
						w.Header().Set("Content-Type", "application/json")
						_, _ = w.Write(append(blockedResp, '\n'))
						return
					}
				}

				violation := s.engine.EvaluateToolCall(params.Name, params.Arguments)
				if violation != nil {
					s.alerts.Dispatch(alert.Event{
						Type:      "policy_violation",
						SessionID: s.sessionID,
						Tool:      params.Name,
						Reason:    violation.Reason,
					})
					s.recorder.RecordEvent(&recorder.Event{
						SessionID:     s.sessionID,
						Timestamp:     time.Now(),
						Direction:     recorder.DirectionHostToServer,
						RPCID:         msg.IDString(),
						Method:        msg.Method,
						ToolName:      params.Name,
						Action:        recorder.ActionBlocked,
						RuleTriggered: violation.RuleName,
						PayloadJSON:   string(body),
					})

					blockedResp, _ := policy.CreateBlockedResponse(msg.ID, violation.RuleName, violation.Reason)
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write(append(blockedResp, '\n'))
					return
				}
			}
		}

		if msg.Method == "resources/read" || msg.Method == "resources/subscribe" {
			var rParams struct {
				URI string `json:"uri"`
			}
			_ = json.Unmarshal(msg.Params, &rParams)
			if violation := s.engine.EvaluateResource(rParams.URI); violation != nil {
				s.alerts.Dispatch(alert.Event{
					Type:      "policy_violation",
					SessionID: s.sessionID,
					Tool:      msg.Method,
					Reason:    violation.Reason,
				})
				s.recorder.RecordEvent(&recorder.Event{
					SessionID:     s.sessionID,
					Timestamp:     time.Now(),
					Direction:     recorder.DirectionHostToServer,
					RPCID:         msg.IDString(),
					Method:        msg.Method,
					ToolName:      "resource:" + rParams.URI,
					Action:        recorder.ActionBlocked,
					RuleTriggered: violation.RuleName,
					PayloadJSON:   string(body),
				})
				blockedResp, _ := policy.CreateBlockedResponse(msg.ID, violation.RuleName, violation.Reason)
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write(append(blockedResp, '\n'))
				return
			}
		}

		if msg.Method == "prompts/get" {
			var prParams struct {
				Name string `json:"name"`
			}
			_ = json.Unmarshal(msg.Params, &prParams)
			if violation := s.engine.EvaluatePrompt(prParams.Name); violation != nil {
				s.alerts.Dispatch(alert.Event{
					Type:      "policy_violation",
					SessionID: s.sessionID,
					Tool:      msg.Method,
					Reason:    violation.Reason,
				})
				s.recorder.RecordEvent(&recorder.Event{
					SessionID:     s.sessionID,
					Timestamp:     time.Now(),
					Direction:     recorder.DirectionHostToServer,
					RPCID:         msg.IDString(),
					Method:        msg.Method,
					ToolName:      "prompt:" + prParams.Name,
					Action:        recorder.ActionBlocked,
					RuleTriggered: violation.RuleName,
					PayloadJSON:   string(body),
				})
				blockedResp, _ := policy.CreateBlockedResponse(msg.ID, violation.RuleName, violation.Reason)
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write(append(blockedResp, '\n'))
				return
			}
		}
	}

	// Forward allowed request upstream
	upstreamReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, s.upstreamURL+r.URL.Path, bytes.NewReader(body))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	upstreamReq.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(upstreamReq)
	if err != nil {
		http.Error(w, fmt.Sprintf("Upstream forward error: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	var scrubbed []byte
	var redactions int
	if s.vault != nil {
		scrubbed, redactions = s.scrubber.ScrubWithVault(respBody, s.vault)
	} else {
		scrubbed, redactions = s.scrubber.Scrub(respBody)
	}

	action := recorder.ActionAllowed
	if redactions > 0 {
		action = recorder.ActionRedacted
	}

	s.recorder.RecordEvent(&recorder.Event{
		SessionID:   s.sessionID,
		Timestamp:   time.Now(),
		Direction:   recorder.DirectionServerToHost,
		RPCID:       msg.IDString(),
		Method:      msg.Method,
		Action:      action,
		PayloadJSON: string(scrubbed),
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(scrubbed)
}
