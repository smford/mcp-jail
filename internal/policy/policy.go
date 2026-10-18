package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/smford/mcp-jail/internal/config"
)

// Violation represents a policy check failure.
type Violation struct {
	RuleName string `json:"rule_name"`
	Reason   string `json:"reason"`
}

// Engine evaluates MCP tool calls against security and budget policies.
type Engine struct {
	cfg     *config.Config
	cwd     string
	homeDir string

	mu             sync.Mutex
	callTimestamps []time.Time
	totalCalls     int
	sessionTokens  int64

	compiledAllowedTools []*regexp.Regexp
	compiledDeniedTools  []*regexp.Regexp
	compiledCommands     []*regexp.Regexp
	resolvedAllowedRoots []string
	resolvedDeniedPaths  []string
}

// NewEngine constructs a new policy Engine.
func NewEngine(cfg *config.Config, cwd string) (*Engine, error) {
	if cwd == "" {
		var err error
		cwd, err = os.Getwd()
		if err != nil {
			cwd = "."
		}
	}
	cwd = filepath.Clean(cwd)

	homeDir := ""
	if u, err := user.Current(); err == nil && u.HomeDir != "" {
		homeDir = u.HomeDir
	} else {
		homeDir = os.Getenv("HOME")
	}
	if homeDir != "" {
		homeDir = filepath.Clean(homeDir)
	}

	e := &Engine{
		cfg:     cfg,
		cwd:     cwd,
		homeDir: homeDir,
	}

	// Compile tool regexes
	for _, pattern := range cfg.Tools.Allowed {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid allowed tool pattern %q: %w", pattern, err)
		}
		e.compiledAllowedTools = append(e.compiledAllowedTools, re)
	}

	for _, pattern := range cfg.Tools.Denied {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid denied tool pattern %q: %w", pattern, err)
		}
		e.compiledDeniedTools = append(e.compiledDeniedTools, re)
	}

	// Compile command regexes
	if cfg.Commands.Enabled {
		for _, pattern := range cfg.Commands.DeniedPatterns {
			re, err := regexp.Compile(pattern)
			if err != nil {
				return nil, fmt.Errorf("invalid command pattern %q: %w", pattern, err)
			}
			e.compiledCommands = append(e.compiledCommands, re)
		}
	}

	// Resolve allowed roots
	if cfg.Filesystem.Enabled {
		for _, root := range cfg.Filesystem.AllowedRoots {
			r := e.expandHome(root)
			if !filepath.IsAbs(r) {
				r = filepath.Join(cwd, r)
			}
			r = filepath.Clean(r)
			e.resolvedAllowedRoots = append(e.resolvedAllowedRoots, r)
		}

		// Prepare denied paths with ~ expanded
		for _, p := range cfg.Filesystem.DeniedPaths {
			exp := e.expandHome(p)
			e.resolvedDeniedPaths = append(e.resolvedDeniedPaths, exp)
		}
	}

	return e, nil
}

func (e *Engine) expandHome(p string) string {
	if e.homeDir == "" {
		return p
	}
	if p == "~" {
		return e.homeDir
	}
	if strings.HasPrefix(p, "~/") || strings.HasPrefix(p, `~\`) {
		return filepath.Join(e.homeDir, p[2:])
	}
	return p
}

// EvaluateToolCall checks a tool call against all configured policies.
// Returns a Violation if blocked, or nil if permitted.
func (e *Engine) EvaluateToolCall(toolName string, arguments map[string]interface{}) *Violation {
	e.mu.Lock()
	defer e.mu.Unlock()

	// 1. Rate & Budget Limits
	if v := e.checkLimits(); v != nil {
		return v
	}

	// Record this call attempt towards session limits
	now := time.Now()
	e.callTimestamps = append(e.callTimestamps, now)
	e.totalCalls++

	// 2. Tool Allow/Deny List
	if v := e.checkToolName(toolName); v != nil {
		return v
	}

	// 3. Command Argument Guard
	if e.cfg.Commands.Enabled {
		if v := e.checkCommandGuard(arguments); v != nil {
			return v
		}
	}

	// 4. Filesystem Boundary Enforcement
	if e.cfg.Filesystem.Enabled {
		if v := e.checkFilesystem(arguments); v != nil {
			return v
		}
	}

	return nil
}

// AddTokens increments cumulative tokens and checks budget.
func (e *Engine) AddTokens(tokens int64) *Violation {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.sessionTokens += tokens
	if e.cfg.Limits.MaxSessionTokens > 0 && e.sessionTokens > e.cfg.Limits.MaxSessionTokens {
		return &Violation{
			RuleName: "rate_budget_session_tokens",
			Reason: fmt.Sprintf("Session token budget exceeded: %d tokens used (limit %d)",
				e.sessionTokens, e.cfg.Limits.MaxSessionTokens),
		}
	}
	return nil
}

// Stats returns the current session policy metrics.
func (e *Engine) Stats() (totalCalls int, sessionTokens int64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.totalCalls, e.sessionTokens
}

func (e *Engine) checkToolName(name string) *Violation {
	// Check allowlist if configured
	if len(e.compiledAllowedTools) > 0 {
		allowed := false
		for _, re := range e.compiledAllowedTools {
			if re.MatchString(name) {
				allowed = true
				break
			}
		}
		if !allowed {
			return &Violation{
				RuleName: "tool_allowlist",
				Reason:   fmt.Sprintf("Tool %q is not in the allowed list", name),
			}
		}
	}

	// Check denylist
	for _, re := range e.compiledDeniedTools {
		if re.MatchString(name) {
			return &Violation{
				RuleName: "tool_denylist",
				Reason:   fmt.Sprintf("Tool %q matches denied pattern %q", name, re.String()),
			}
		}
	}

	return nil
}

func (e *Engine) checkLimits() *Violation {
	// Total calls limit
	if e.cfg.Limits.MaxTotalCallsPerSession > 0 && e.totalCalls >= e.cfg.Limits.MaxTotalCallsPerSession {
		return &Violation{
			RuleName: "rate_budget_total_calls",
			Reason: fmt.Sprintf("Session total tool call limit reached (%d calls)",
				e.cfg.Limits.MaxTotalCallsPerSession),
		}
	}

	// Rate per minute limit (sliding 60s window)
	if e.cfg.Limits.MaxToolCallsPerMinute > 0 {
		cutoff := time.Now().Add(-1 * time.Minute)
		idx := 0
		for idx < len(e.callTimestamps) && e.callTimestamps[idx].Before(cutoff) {
			idx++
		}
		e.callTimestamps = e.callTimestamps[idx:]

		if len(e.callTimestamps) >= e.cfg.Limits.MaxToolCallsPerMinute {
			return &Violation{
				RuleName: "rate_budget_calls_per_minute",
				Reason: fmt.Sprintf("Rate limit exceeded: %d calls in the last minute (limit %d)",
					len(e.callTimestamps), e.cfg.Limits.MaxToolCallsPerMinute),
			}
		}
	}

	// Cumulative session tokens limit
	if e.cfg.Limits.MaxSessionTokens > 0 && e.sessionTokens >= e.cfg.Limits.MaxSessionTokens {
		return &Violation{
			RuleName: "rate_budget_session_tokens",
			Reason: fmt.Sprintf("Session token budget exceeded: %d tokens used (limit %d)",
				e.sessionTokens, e.cfg.Limits.MaxSessionTokens),
		}
	}

	return nil
}

func (e *Engine) checkCommandGuard(arguments map[string]interface{}) *Violation {
	stringsList := extractStringValues("", arguments)
	for _, item := range stringsList {
		for _, re := range e.compiledCommands {
			if re.MatchString(item.Value) {
				return &Violation{
					RuleName: "command_guard",
					Reason:   fmt.Sprintf("Argument in field %q matched dangerous command pattern: %s", item.Key, re.String()),
				}
			}
		}
	}
	return nil
}

func (e *Engine) checkFilesystem(arguments map[string]interface{}) *Violation {
	items := extractStringValues("", arguments)

	for _, item := range items {
		val := strings.TrimSpace(item.Value)
		if val == "" {
			continue
		}

		// Also check space-separated tokens in command arguments (e.g., `cat ~/.ssh/id_rsa`)
		candidates := []string{val}
		tokens := strings.Fields(val)
		if len(tokens) > 1 {
			for _, tok := range tokens {
				if looksLikePath(tok) {
					candidates = append(candidates, tok)
				}
			}
		}

		for _, cand := range candidates {
			if v := e.checkPathCandidate(cand, item.Key); v != nil {
				return v
			}
		}
	}

	return nil
}

func looksLikePath(s string) bool {
	if strings.HasPrefix(s, "/") || strings.HasPrefix(s, "./") || strings.HasPrefix(s, "../") ||
		strings.HasPrefix(s, "~/") || strings.HasPrefix(s, `~\`) || strings.HasPrefix(s, ".env") {
		return true
	}
	if strings.Contains(s, "/") || strings.Contains(s, `\`) {
		return true
	}
	return false
}

func isPathKey(key string) bool {
	k := strings.ToLower(key)
	return strings.Contains(k, "path") ||
		strings.Contains(k, "file") ||
		strings.Contains(k, "dir") ||
		strings.Contains(k, "dest") ||
		strings.Contains(k, "src") ||
		strings.Contains(k, "root") ||
		strings.Contains(k, "target") ||
		strings.Contains(k, "cwd")
}

func (e *Engine) checkPathCandidate(cand string, keyName string) *Violation {
	candExp := e.expandHome(cand)

	// 1. Check against denied paths (globs)
	for _, pattern := range e.resolvedDeniedPaths {
		// Test raw/expanded candidate
		if match, _ := doublestar.Match(pattern, cand); match {
			return &Violation{
				RuleName: "filesystem_boundary",
				Reason:   fmt.Sprintf("Access to path %q is denied by pattern %q", cand, pattern),
			}
		}
		if match, _ := doublestar.Match(pattern, candExp); match {
			return &Violation{
				RuleName: "filesystem_boundary",
				Reason:   fmt.Sprintf("Access to path %q is denied by pattern %q", cand, pattern),
			}
		}

		// Test resolved absolute path
		absPath := candExp
		if !filepath.IsAbs(absPath) {
			absPath = filepath.Join(e.cwd, absPath)
		}
		absPath = filepath.Clean(absPath)
		if match, _ := doublestar.Match(pattern, absPath); match {
			return &Violation{
				RuleName: "filesystem_boundary",
				Reason:   fmt.Sprintf("Access to resolved path %q is denied by pattern %q", absPath, pattern),
			}
		}

		// Also check symlink target if path exists
		if target, err := filepath.EvalSymlinks(absPath); err == nil && target != absPath {
			if match, _ := doublestar.Match(pattern, target); match {
				return &Violation{
					RuleName: "filesystem_boundary",
					Reason:   fmt.Sprintf("Access to symlink target %q is denied by pattern %q", target, pattern),
				}
			}
		}
	}

	// 2. Check against allowed roots
	// We only enforce allowed roots on candidates that are explicitly path keys
	// or look distinctly like file paths (starting with /, ~, ., or containing path separators)
	if len(e.resolvedAllowedRoots) > 0 && (looksLikePath(cand) || isPathKey(keyName)) {
		absPath := candExp
		if !filepath.IsAbs(absPath) {
			absPath = filepath.Join(e.cwd, absPath)
		}
		absPath = filepath.Clean(absPath)

		// Also resolve symlink if possible
		resolvedPath := absPath
		if target, err := filepath.EvalSymlinks(absPath); err == nil {
			resolvedPath = target
		}

		withinAllowed := false
		for _, root := range e.resolvedAllowedRoots {
			// Check if absPath or resolvedPath is inside root
			if isSubpath(root, absPath) || isSubpath(root, resolvedPath) {
				withinAllowed = true
				break
			}
		}

		if !withinAllowed {
			return &Violation{
				RuleName: "filesystem_boundary",
				Reason: fmt.Sprintf("Path %q (resolved: %q) falls outside allowed workspace roots",
					cand, absPath),
			}
		}
	}

	return nil
}

func isSubpath(parent, child string) bool {
	parent = filepath.Clean(parent)
	child = filepath.Clean(child)

	if parent == child {
		return true
	}

	rel, err := filepath.Rel(parent, child)
	if err != nil {
		return false
	}

	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return false
	}
	return true
}

type keyVal struct {
	Key   string
	Value string
}

func extractStringValues(prefix string, obj interface{}) []keyVal {
	var result []keyVal
	if obj == nil {
		return result
	}

	switch v := obj.(type) {
	case string:
		result = append(result, keyVal{Key: prefix, Value: v})
	case []interface{}:
		for i, item := range v {
			subKey := fmt.Sprintf("%s[%d]", prefix, i)
			result = append(result, extractStringValues(subKey, item)...)
		}
	case map[string]interface{}:
		for k, val := range v {
			subKey := k
			if prefix != "" {
				subKey = prefix + "." + k
			}
			result = append(result, extractStringValues(subKey, val)...)
		}
	case json.Number:
		// Not a string
	}

	return result
}
