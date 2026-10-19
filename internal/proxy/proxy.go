package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/smford/mcp-jail/internal/alert"
	"github.com/smford/mcp-jail/internal/config"
	"github.com/smford/mcp-jail/internal/policy"
	"github.com/smford/mcp-jail/internal/ratelimit"
	"github.com/smford/mcp-jail/internal/recorder"
	"github.com/smford/mcp-jail/internal/sandbox"
	"github.com/smford/mcp-jail/internal/scrubber"
	"github.com/smford/mcp-jail/internal/vault"
)

const (
	// MaxLineSize supports up to 16MB single-line JSON-RPC payloads.
	MaxLineSize = 16 * 1024 * 1024
	initBufSize = 64 * 1024
)

// Learner receives tool invocations to synthesize least-privilege security policies.
type Learner interface {
	RecordToolCall(name string, args map[string]interface{})
	AddTokens(tokens int64)
}

// Options holds configuration and runtime options for the Proxy.
type Options struct {
	Config    *config.Config
	SessionID string
	DBPath    string
	DryRun    bool
	Command   string
	Args      []string
	Cwd       string
	Env       []string
	Learner   Learner

	RemoteURL string            // Upstream HTTP URL for remote MCP server (bridge mode)
	Headers   map[string]string // HTTP headers for upstream requests

	// Overridable IO streams (for testing)
	HostIn  io.Reader
	HostOut io.Writer
	HostErr io.Writer
}

type pendingCall struct {
	ToolName  string
	StartTime time.Time
}

// Proxy coordinates bidirectional stdio inspection between the host agent and MCP server.
type Proxy struct {
	opts          Options
	engine        *policy.Engine
	scrubber      *scrubber.Scrubber
	recorder      *recorder.Recorder
	vault         *vault.Vault
	limiter       *ratelimit.Limiter
	alerts        *alert.Dispatcher
	sandboxDriver sandbox.Driver

	hostOutMu sync.Mutex
	hostOut   io.Writer
	hostErr   io.Writer

	pendingMu sync.Mutex
	pending   map[string]pendingCall

	totalCalls      int
	blockedCalls    int
	redactedSecrets int
	estTokens       int64
	metricsMu       sync.Mutex
}

// NewProxy creates and initializes a Proxy instance.
func NewProxy(opts Options) (*Proxy, error) {
	if opts.SessionID == "" {
		opts.SessionID = uuid.New().String()
	}

	if opts.Cwd == "" {
		cwd, err := os.Getwd()
		if err != nil {
			cwd = "."
		}
		opts.Cwd = cwd
	}

	if opts.HostIn == nil {
		opts.HostIn = os.Stdin
	}
	if opts.HostOut == nil {
		opts.HostOut = os.Stdout
	}
	if opts.HostErr == nil {
		opts.HostErr = os.Stderr
	}

	if opts.DryRun {
		opts.Config.Settings.DryRun = true
	}

	engine, err := policy.NewEngine(opts.Config, opts.Cwd)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize policy engine: %w", err)
	}

	sc, err := scrubber.NewScrubber(opts.Config.Scrubber)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize secret scrubber: %w", err)
	}

	rec, err := recorder.NewRecorder(opts.DBPath)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize flight recorder: %w", err)
	}

	var v *vault.Vault
	if opts.Config.Vault.Enabled {
		v = vault.NewVault()
	}

	lmt := ratelimit.NewLimiter(opts.Config.Limits)
	alt := alert.NewDispatcher(opts.Config.Alerts)
	sbDriver := sandbox.NewDriver(opts.Config.Sandbox)

	return &Proxy{
		opts:          opts,
		engine:        engine,
		scrubber:      sc,
		recorder:      rec,
		vault:         v,
		limiter:       lmt,
		alerts:        alt,
		sandboxDriver: sbDriver,
		hostOut:       opts.HostOut,
		hostErr:       opts.HostErr,
		pending:       make(map[string]pendingCall),
	}, nil
}

// Run executes the child MCP process and intercepts stdio streams until completion.
func (p *Proxy) Run(ctx context.Context) (int, error) {
	if p.opts.RemoteURL != "" {
		return p.RunRemote(ctx)
	}

	cmdStr := p.opts.Command
	if len(p.opts.Args) > 0 {
		cmdStr = fmt.Sprintf("%s %v", p.opts.Command, p.opts.Args)
	}

	// Record start of session
	err := p.recorder.StartSession(&recorder.Session{
		ID:        p.opts.SessionID,
		StartedAt: time.Now(),
		Command:   cmdStr,
		Cwd:       p.opts.Cwd,
	})
	if err != nil {
		fmt.Fprintf(p.hostErr, "[mcp-jail] warning: failed to start session in flight recorder: %v\n", err)
	}

	// Prepare child process
	var child *exec.Cmd
	if p.opts.Config.Sandbox.Enabled && p.sandboxDriver != nil {
		var wrapErr error
		child, wrapErr = p.sandboxDriver.WrapCommand(ctx, p.opts.Command, p.opts.Args, p.opts.Config.Sandbox, p.opts.Config.Filesystem.AllowedRoots)
		if wrapErr != nil {
			child = exec.CommandContext(ctx, p.opts.Command, p.opts.Args...)
		}
	} else {
		child = exec.CommandContext(ctx, p.opts.Command, p.opts.Args...)
	}
	child.Dir = p.opts.Cwd
	if len(p.opts.Env) > 0 {
		child.Env = append(os.Environ(), p.opts.Env...)
	}

	if err := os.MkdirAll(p.opts.Cwd, 0755); err != nil {
		p.closeRecorder()
		return 1, fmt.Errorf("failed to ensure cwd directory %s: %w", p.opts.Cwd, err)
	}

	childIn, err := child.StdinPipe()
	if err != nil {
		p.closeRecorder()
		return 1, fmt.Errorf("failed to create child stdin pipe: %w", err)
	}

	childOut, err := child.StdoutPipe()
	if err != nil {
		p.closeRecorder()
		return 1, fmt.Errorf("failed to create child stdout pipe: %w", err)
	}

	childErr, err := child.StderrPipe()
	if err != nil {
		p.closeRecorder()
		return 1, fmt.Errorf("failed to create child stderr pipe: %w", err)
	}

	if err := child.Start(); err != nil {
		p.closeRecorder()
		return 1, fmt.Errorf("failed to start child process %q: %w", p.opts.Command, err)
	}

	// Handle OS signals for graceful termination
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigChan)

	childDone := make(chan struct{})
	var childErrResult error

	go func() {
		childErrResult = child.Wait()
		close(childDone)
	}()

	go func() {
		select {
		case <-sigChan:
			if child.Process != nil {
				_ = child.Process.Signal(syscall.SIGTERM)
			}
		case <-ctx.Done():
			if child.Process != nil {
				_ = child.Process.Kill()
			}
		case <-childDone:
		}
	}()

	var outWg sync.WaitGroup

	// 1. Child Stderr -> Host Stderr (transparent passthrough)
	outWg.Add(1)
	go func() {
		defer outWg.Done()
		_, _ = io.Copy(p.hostErr, childErr)
	}()

	// 2. Child Stdout -> Host Stdout (Server -> Host: Secret Scrubber + Token Accounting)
	outWg.Add(1)
	go func() {
		defer outWg.Done()
		p.pumpServerToHost(childOut)
	}()

	// 3. Host Stdin -> Child Stdin (Host -> Server: Firewall & Policy Engine)
	hostInDone := make(chan struct{})
	go func() {
		p.pumpHostToServer(p.opts.HostIn, childIn)
		_ = childIn.Close()
		close(hostInDone)
	}()

	// Wait for child process exit or host input EOF
	select {
	case <-childDone:
	case <-hostInDone:
		<-childDone
	}

	// Drain output streams
	outWg.Wait()

	exitCode := 0
	if childErrResult != nil {
		if exitErr, ok := childErrResult.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = 1
		}
	}

	p.metricsMu.Lock()
	tc := p.totalCalls
	bc := p.blockedCalls
	rs := p.redactedSecrets
	et := p.estTokens
	p.metricsMu.Unlock()

	p.recorder.EndSession(p.opts.SessionID, tc, bc, rs, et)
	p.closeRecorder()

	return exitCode, nil
}

func (p *Proxy) closeRecorder() {
	if p.recorder != nil {
		_ = p.recorder.Close()
	}
}

// pumpHostToServer reads from Host stdin, intercepts tools/call, evaluates policy, and forwards to child stdin.
func (p *Proxy) pumpHostToServer(r io.Reader, childIn io.Writer) {
	scanner := bufio.NewScanner(r)
	buf := make([]byte, initBufSize)
	scanner.Buffer(buf, MaxLineSize)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		// Reversible vault detokenization for incoming requests from host
		if p.vault != nil {
			detokenized := p.vault.Detokenize(string(line))
			line = []byte(detokenized)
		}

		msg, err := ParseMessage(line)
		if err != nil {
			// Not valid JSON-RPC, pass through directly
			_, _ = childIn.Write(append(line, '\n'))
			continue
		}

		// 1. Inspect tools/call
		if msg.Method == "tools/call" {
			params, parseErr := msg.ParseToolCallParams()
			if parseErr != nil {
				// Malformed params, pass through
				_, _ = childIn.Write(append(line, '\n'))
				continue
			}

			// Check fine-grained rate limit
			if p.limiter != nil {
				if limErr := p.limiter.RecordToolCall(params.Name); limErr != nil {
					p.metricsMu.Lock()
					p.blockedCalls++
					p.metricsMu.Unlock()

					p.alerts.Dispatch(alert.Event{
						Type:      "rate_limit_exceeded",
						SessionID: p.opts.SessionID,
						Tool:      params.Name,
						Reason:    limErr.Error(),
					})

					ruleName := "rate_limit_exceeded"
					if le, ok := limErr.(*ratelimit.LimitError); ok {
						ruleName = le.RuleName
					}

					p.recordEvent(&recorder.Event{
						SessionID:     p.opts.SessionID,
						Timestamp:     time.Now(),
						Direction:     recorder.DirectionHostToServer,
						RPCID:         msg.IDString(),
						Method:        msg.Method,
						ToolName:      params.Name,
						Action:        recorder.ActionBlocked,
						RuleTriggered: ruleName,
						PayloadJSON:   string(line),
					})

					if !p.opts.DryRun {
						blockedResp, _ := policy.CreateBlockedResponse(msg.ID, ruleName, limErr.Error())
						p.writeHostOut(blockedResp)
						continue
					}
				}
			}

			if p.opts.Learner != nil {
				p.opts.Learner.RecordToolCall(params.Name, params.Arguments)
			}

			// Pre-execution file snapshotting for diff & rollback
			if p.opts.Config.Snapshots.Enabled {
				p.snapshotFileIfModifying(params.Name, params.Arguments)
			}

			// Evaluate policy
			violation := p.engine.EvaluateToolCall(params.Name, params.Arguments)
			if violation != nil {
				p.metricsMu.Lock()
				p.blockedCalls++
				p.metricsMu.Unlock()

				p.alerts.Dispatch(alert.Event{
					Type:      "policy_violation",
					SessionID: p.opts.SessionID,
					Tool:      params.Name,
					Reason:    violation.Reason,
				})

				ruleName := violation.RuleName
				if p.opts.DryRun {
					ruleName += " (dry-run)"
				}

				// Log blocked event
				p.recordEvent(&recorder.Event{
					SessionID:     p.opts.SessionID,
					Timestamp:     time.Now(),
					Direction:     recorder.DirectionHostToServer,
					RPCID:         msg.IDString(),
					Method:        msg.Method,
					ToolName:      params.Name,
					Action:        recorder.ActionBlocked,
					RuleTriggered: ruleName,
					PayloadJSON:   string(line),
				})

				if !p.opts.DryRun {
					// Synthesize and inject graceful blocked response directly to host stdout
					blockedResp, err := policy.CreateBlockedResponse(msg.ID, violation.RuleName, violation.Reason)
					if err == nil {
						p.writeHostOut(blockedResp)
					}
					// Do NOT forward to child server
					continue
				}
			}

			// Tool call allowed
			p.metricsMu.Lock()
			p.totalCalls++
			p.metricsMu.Unlock()

			// Register pending call for latency calculation
			idStr := msg.IDString()
			if idStr != "" {
				p.pendingMu.Lock()
				p.pending[idStr] = pendingCall{
					ToolName:  params.Name,
					StartTime: time.Now(),
				}
				p.pendingMu.Unlock()
			}

			p.recordEvent(&recorder.Event{
				SessionID:     p.opts.SessionID,
				Timestamp:     time.Now(),
				Direction:     recorder.DirectionHostToServer,
				RPCID:         idStr,
				Method:        msg.Method,
				ToolName:      params.Name,
				Action:        recorder.ActionAllowed,
				RuleTriggered: "",
				PayloadJSON:   string(line),
			})
		}

		// 2. Inspect resources/read and resources/subscribe
		if msg.Method == "resources/read" || msg.Method == "resources/subscribe" {
			var rParams struct {
				URI string `json:"uri"`
			}
			_ = json.Unmarshal(msg.Params, &rParams)
			if violation := p.engine.EvaluateResource(rParams.URI); violation != nil {
				p.metricsMu.Lock()
				p.blockedCalls++
				p.metricsMu.Unlock()

				p.alerts.Dispatch(alert.Event{
					Type:      "policy_violation",
					SessionID: p.opts.SessionID,
					Tool:      msg.Method,
					Reason:    violation.Reason,
				})

				p.recordEvent(&recorder.Event{
					SessionID:     p.opts.SessionID,
					Timestamp:     time.Now(),
					Direction:     recorder.DirectionHostToServer,
					RPCID:         msg.IDString(),
					Method:        msg.Method,
					ToolName:      "resource:" + rParams.URI,
					Action:        recorder.ActionBlocked,
					RuleTriggered: violation.RuleName,
					PayloadJSON:   string(line),
				})

				if !p.opts.DryRun {
					blockedResp, _ := policy.CreateBlockedResponse(msg.ID, violation.RuleName, violation.Reason)
					p.writeHostOut(blockedResp)
					continue
				}
			}
		}

		// 3. Inspect prompts/get
		if msg.Method == "prompts/get" {
			var prParams struct {
				Name string `json:"name"`
			}
			_ = json.Unmarshal(msg.Params, &prParams)
			if violation := p.engine.EvaluatePrompt(prParams.Name); violation != nil {
				p.metricsMu.Lock()
				p.blockedCalls++
				p.metricsMu.Unlock()

				p.alerts.Dispatch(alert.Event{
					Type:      "policy_violation",
					SessionID: p.opts.SessionID,
					Tool:      msg.Method,
					Reason:    violation.Reason,
				})

				p.recordEvent(&recorder.Event{
					SessionID:     p.opts.SessionID,
					Timestamp:     time.Now(),
					Direction:     recorder.DirectionHostToServer,
					RPCID:         msg.IDString(),
					Method:        msg.Method,
					ToolName:      "prompt:" + prParams.Name,
					Action:        recorder.ActionBlocked,
					RuleTriggered: violation.RuleName,
					PayloadJSON:   string(line),
				})

				if !p.opts.DryRun {
					blockedResp, _ := policy.CreateBlockedResponse(msg.ID, violation.RuleName, violation.Reason)
					p.writeHostOut(blockedResp)
					continue
				}
			}
		}

		// Forward to child MCP server
		_, _ = childIn.Write(append(line, '\n'))
	}
}

// pumpServerToHost reads from child stdout, redacts secrets, calculates latency and tokens, and writes to Host stdout.
func (p *Proxy) pumpServerToHost(r io.Reader) {
	scanner := bufio.NewScanner(r)
	buf := make([]byte, initBufSize)
	scanner.Buffer(buf, MaxLineSize)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		msg, err := ParseMessage(line)
		var latencyMs int64
		var toolName string
		rpcID := ""

		if err == nil {
			rpcID = msg.IDString()
			if rpcID != "" {
				p.pendingMu.Lock()
				if pc, ok := p.pending[rpcID]; ok {
					latencyMs = time.Since(pc.StartTime).Milliseconds()
					toolName = pc.ToolName
					delete(p.pending, rpcID)
				}
				p.pendingMu.Unlock()
			}

			// Inspect sampling/createMessage requests from child server
			if msg.Method == "sampling/createMessage" {
				if violation := p.engine.InspectSamplingMessage(msg.Params); violation != nil {
					p.metricsMu.Lock()
					p.blockedCalls++
					p.metricsMu.Unlock()

					p.alerts.Dispatch(alert.Event{
						Type:      "prompt_injection_detected",
						SessionID: p.opts.SessionID,
						Tool:      "sampling/createMessage",
						Reason:    violation.Reason,
					})

					p.recordEvent(&recorder.Event{
						SessionID:     p.opts.SessionID,
						Timestamp:     time.Now(),
						Direction:     recorder.DirectionServerToHost,
						RPCID:         rpcID,
						Method:        msg.Method,
						ToolName:      "sampling",
						Action:        recorder.ActionBlocked,
						RuleTriggered: violation.RuleName,
						PayloadJSON:   string(line),
					})
					// Drop prompt injection attempt
					continue
				}
			}
		}

		// Scrub outbound secrets BEFORE forwarding to Host stdout (using Vault if enabled)
		var scrubbedBytes []byte
		var redactions int
		if p.vault != nil {
			scrubbedBytes, redactions = p.scrubber.ScrubWithVault(line, p.vault)
		} else {
			scrubbedBytes, redactions = p.scrubber.Scrub(line)
		}

		// Estimate tokens: len(payload)/4
		tokens := int64(len(scrubbedBytes)) / 4
		if tokens == 0 && len(scrubbedBytes) > 0 {
			tokens = 1
		}

		p.metricsMu.Lock()
		p.redactedSecrets += redactions
		p.estTokens += tokens
		p.metricsMu.Unlock()

		_ = p.engine.AddTokens(tokens)
		if p.limiter != nil {
			_ = p.limiter.RecordTokens(tokens)
		}
		if p.opts.Learner != nil {
			p.opts.Learner.AddTokens(tokens)
		}

		action := recorder.ActionAllowed
		if redactions > 0 {
			action = recorder.ActionRedacted
		}

		p.recordEvent(&recorder.Event{
			SessionID:     p.opts.SessionID,
			Timestamp:     time.Now(),
			Direction:     recorder.DirectionServerToHost,
			RPCID:         rpcID,
			Method:        msg.Method,
			ToolName:      toolName,
			Action:        action,
			RuleTriggered: "",
			LatencyMs:     latencyMs,
			PayloadJSON:   string(scrubbedBytes),
		})

		// Write scrubbed response to Host stdout
		p.writeHostOut(scrubbedBytes)
	}
}

func (p *Proxy) recordEvent(ev *recorder.Event) {
	p.recorder.RecordEvent(ev)
	if p.opts.Config.Export.Enabled && p.opts.Config.Export.File != "" {
		p.exportEvent(ev)
	}
}

func (p *Proxy) exportEvent(ev *recorder.Event) {
	filePath := recorder.ExpandPath(p.opts.Config.Export.File)
	data, err := json.Marshal(ev)
	if err != nil {
		return
	}
	f, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err == nil {
		defer f.Close()
		_, _ = f.Write(append(data, '\n'))
	}
}

func (p *Proxy) snapshotFileIfModifying(toolName string, args map[string]interface{}) {
	var targetPaths []string
	for k, v := range args {
		kLower := strings.ToLower(k)
		if strings.Contains(kLower, "path") || strings.Contains(kLower, "file") || strings.Contains(kLower, "dest") {
			if strVal, ok := v.(string); ok && strVal != "" {
				targetPaths = append(targetPaths, strVal)
			}
		}
	}

	maxBytes := int64(p.opts.Config.Snapshots.MaxFileSizeKB) * 1024
	if maxBytes <= 0 {
		maxBytes = 512 * 1024
	}

	for _, relPath := range targetPaths {
		absPath := relPath
		if !filepath.IsAbs(absPath) {
			absPath = filepath.Join(p.opts.Cwd, absPath)
		}
		absPath = filepath.Clean(absPath)

		info, err := os.Stat(absPath)
		if err != nil || info.IsDir() || info.Size() > maxBytes {
			continue
		}

		has, err := p.recorder.HasSnapshot(p.opts.SessionID, absPath)
		if err != nil || has {
			continue
		}

		content, err := os.ReadFile(absPath)
		if err == nil {
			_ = p.recorder.SaveSnapshot(p.opts.SessionID, absPath, content)
		}
	}
}

func (p *Proxy) writeHostOut(data []byte) {
	p.hostOutMu.Lock()
	defer p.hostOutMu.Unlock()
	_, _ = p.hostOut.Write(append(data, '\n'))
}

// RunRemote runs a stdio-to-HTTP JSON-RPC bridge for remote MCP servers.
func (p *Proxy) RunRemote(ctx context.Context) (int, error) {
	cmdStr := "remote -> " + p.opts.RemoteURL

	err := p.recorder.StartSession(&recorder.Session{
		ID:        p.opts.SessionID,
		StartedAt: time.Now(),
		Command:   cmdStr,
		Cwd:       p.opts.Cwd,
	})
	if err != nil {
		fmt.Fprintf(p.hostErr, "[mcp-jail] warning: failed to start session in flight recorder: %v\n", err)
	}

	httpClient := &http.Client{
		Timeout: 60 * time.Second,
	}

	scanner := bufio.NewScanner(p.opts.HostIn)
	buf := make([]byte, initBufSize)
	scanner.Buffer(buf, MaxLineSize)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}

		if p.vault != nil {
			detokenized := p.vault.Detokenize(string(line))
			line = []byte(detokenized)
		}

		msg, parseErr := ParseMessage(line)
		if parseErr == nil {
			if msg.Method == "tools/call" {
				params, err := msg.ParseToolCallParams()
				if err == nil {
					// Check rate limits
					if p.limiter != nil {
						if limErr := p.limiter.RecordToolCall(params.Name); limErr != nil {
							p.alerts.Dispatch(alert.Event{
								Type:      "rate_limit_exceeded",
								SessionID: p.opts.SessionID,
								Tool:      params.Name,
								Reason:    limErr.Error(),
							})
							ruleName := "rate_limit_exceeded"
							if le, ok := limErr.(*ratelimit.LimitError); ok {
								ruleName = le.RuleName
							}
							p.recordEvent(&recorder.Event{
								SessionID:     p.opts.SessionID,
								Timestamp:     time.Now(),
								Direction:     recorder.DirectionHostToServer,
								RPCID:         msg.IDString(),
								Method:        msg.Method,
								ToolName:      params.Name,
								Action:        recorder.ActionBlocked,
								RuleTriggered: ruleName,
								PayloadJSON:   string(line),
							})
							blockedResp, _ := policy.CreateBlockedResponse(msg.ID, ruleName, limErr.Error())
							p.writeHostOut(blockedResp)
							continue
						}
					}

					// Evaluate security policy
					violation := p.engine.EvaluateToolCall(params.Name, params.Arguments)
					if violation != nil {
						p.alerts.Dispatch(alert.Event{
							Type:      "policy_violation",
							SessionID: p.opts.SessionID,
							Tool:      params.Name,
							Reason:    violation.Reason,
						})
						p.recordEvent(&recorder.Event{
							SessionID:     p.opts.SessionID,
							Timestamp:     time.Now(),
							Direction:     recorder.DirectionHostToServer,
							RPCID:         msg.IDString(),
							Method:        msg.Method,
							ToolName:      params.Name,
							Action:        recorder.ActionBlocked,
							RuleTriggered: violation.RuleName,
							PayloadJSON:   string(line),
						})
						blockedResp, _ := policy.CreateBlockedResponse(msg.ID, violation.RuleName, violation.Reason)
						p.writeHostOut(blockedResp)
						continue
					}
				}
			}

			if msg.Method == "resources/read" {
				var rParams struct {
					URI string `json:"uri"`
				}
				_ = json.Unmarshal(msg.Params, &rParams)
				if violation := p.engine.EvaluateResource(rParams.URI); violation != nil {
					p.alerts.Dispatch(alert.Event{
						Type:      "policy_violation",
						SessionID: p.opts.SessionID,
						Tool:      msg.Method,
						Reason:    violation.Reason,
					})
					p.recordEvent(&recorder.Event{
						SessionID:     p.opts.SessionID,
						Timestamp:     time.Now(),
						Direction:     recorder.DirectionHostToServer,
						RPCID:         msg.IDString(),
						Method:        msg.Method,
						ToolName:      "resource:" + rParams.URI,
						Action:        recorder.ActionBlocked,
						RuleTriggered: violation.RuleName,
						PayloadJSON:   string(line),
					})
					blockedResp, _ := policy.CreateBlockedResponse(msg.ID, violation.RuleName, violation.Reason)
					p.writeHostOut(blockedResp)
					continue
				}
			}

			if msg.Method == "prompts/get" {
				var prParams struct {
					Name string `json:"name"`
				}
				_ = json.Unmarshal(msg.Params, &prParams)
				if violation := p.engine.EvaluatePrompt(prParams.Name); violation != nil {
					p.alerts.Dispatch(alert.Event{
						Type:      "policy_violation",
						SessionID: p.opts.SessionID,
						Tool:      msg.Method,
						Reason:    violation.Reason,
					})
					p.recordEvent(&recorder.Event{
						SessionID:     p.opts.SessionID,
						Timestamp:     time.Now(),
						Direction:     recorder.DirectionHostToServer,
						RPCID:         msg.IDString(),
						Method:        msg.Method,
						ToolName:      "prompt:" + prParams.Name,
						Action:        recorder.ActionBlocked,
						RuleTriggered: violation.RuleName,
						PayloadJSON:   string(line),
					})
					blockedResp, _ := policy.CreateBlockedResponse(msg.ID, violation.RuleName, violation.Reason)
					p.writeHostOut(blockedResp)
					continue
				}
			}
		}

		// Forward request to remote MCP server over HTTP POST
		startTime := time.Now()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.opts.RemoteURL, bytes.NewReader(line))
		if err != nil {
			if msg != nil && msg.ID != nil {
				errResp := fmt.Sprintf(`{"jsonrpc":"2.0","id":%v,"error":{"code":-32603,"message":%q}}`, msg.IDString(), err.Error())
				p.writeHostOut([]byte(errResp))
			}
			continue
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		for k, v := range p.opts.Headers {
			req.Header.Set(k, v)
		}

		resp, err := httpClient.Do(req)
		if err != nil {
			if msg != nil && msg.ID != nil {
				errResp := fmt.Sprintf(`{"jsonrpc":"2.0","id":%v,"error":{"code":-32603,"message":"upstream connection error: %s"}}`, msg.IDString(), err.Error())
				p.writeHostOut([]byte(errResp))
			}
			continue
		}

		respBody, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		latencyMs := time.Since(startTime).Milliseconds()

		if msg != nil && msg.ID != nil {
			var scrubbed []byte
			var redactions int
			if p.vault != nil {
				scrubbed, redactions = p.scrubber.ScrubWithVault(respBody, p.vault)
			} else {
				scrubbed, redactions = p.scrubber.Scrub(respBody)
			}

			action := recorder.ActionAllowed
			if redactions > 0 {
				action = recorder.ActionRedacted
			}

			p.recordEvent(&recorder.Event{
				SessionID:   p.opts.SessionID,
				Timestamp:   time.Now(),
				Direction:   recorder.DirectionServerToHost,
				RPCID:       msg.IDString(),
				Method:      msg.Method,
				Action:      action,
				LatencyMs:   latencyMs,
				PayloadJSON: string(scrubbed),
			})

			p.writeHostOut(scrubbed)
		}
	}

	p.metricsMu.Lock()
	tc := p.totalCalls
	bc := p.blockedCalls
	rs := p.redactedSecrets
	et := p.estTokens
	p.metricsMu.Unlock()

	p.recorder.EndSession(p.opts.SessionID, tc, bc, rs, et)
	p.closeRecorder()

	return 0, scanner.Err()
}
