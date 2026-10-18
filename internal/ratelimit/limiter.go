package ratelimit

import (
	"fmt"
	"sync"
	"time"

	"github.com/smford/mcp-jail/internal/config"
)

// Limiter manages rate limits per tool, globally per minute, total per session, and token spend quotas.
type Limiter struct {
	mu           sync.Mutex
	cfg          config.LimitsConfig
	globalCalls  []time.Time
	toolCalls    map[string][]time.Time
	totalCalls   int
	totalTokens  int64
	toolLimitCfg map[string]config.ToolRateLimitConfig
}

// NewLimiter creates a new rate and budget limiter.
func NewLimiter(cfg config.LimitsConfig) *Limiter {
	toolMap := make(map[string]config.ToolRateLimitConfig)
	for _, tl := range cfg.ToolLimits {
		if tl.Tool != "" {
			toolMap[tl.Tool] = tl
		}
	}

	return &Limiter{
		cfg:          cfg,
		toolCalls:    make(map[string][]time.Time),
		toolLimitCfg: toolMap,
	}
}

// LimitError represents a rate limit violation with its associated rule name.
type LimitError struct {
	RuleName string
	Message  string
}

func (e *LimitError) Error() string {
	return e.Message
}

// RecordToolCall checks and records an execution of the given tool name.
// Returns an error if any limit is exceeded.
func (l *Limiter) RecordToolCall(tool string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	oneMinAgo := now.Add(-1 * time.Minute)
	oneHourAgo := now.Add(-1 * time.Hour)

	// 1. Session total calls limit
	if l.cfg.MaxTotalCallsPerSession > 0 && l.totalCalls >= l.cfg.MaxTotalCallsPerSession {
		return &LimitError{
			RuleName: "rate_budget_total_calls",
			Message:  fmt.Sprintf("Maximum tool calls per session exceeded (%d)", l.cfg.MaxTotalCallsPerSession),
		}
	}

	// 2. Global calls per minute limit
	if l.cfg.MaxToolCallsPerMinute > 0 {
		var recentGlobal []time.Time
		for _, t := range l.globalCalls {
			if t.After(oneMinAgo) {
				recentGlobal = append(recentGlobal, t)
			}
		}
		l.globalCalls = recentGlobal

		if len(l.globalCalls) >= l.cfg.MaxToolCallsPerMinute {
			return &LimitError{
				RuleName: "rate_budget_tool_calls_per_minute",
				Message:  fmt.Sprintf("Tool call rate limit exceeded (%d/minute)", l.cfg.MaxToolCallsPerMinute),
			}
		}
	}

	// 3. Per-tool specific rate limits
	if tl, exists := l.toolLimitCfg[tool]; exists {
		calls := l.toolCalls[tool]
		var recentMin []time.Time
		var recentHour []time.Time

		for _, t := range calls {
			if t.After(oneMinAgo) {
				recentMin = append(recentMin, t)
			}
			if t.After(oneHourAgo) {
				recentHour = append(recentHour, t)
			}
		}

		if tl.MaxPerMinute > 0 && len(recentMin) >= tl.MaxPerMinute {
			return &LimitError{
				RuleName: "rate_budget_tool_limit",
				Message:  fmt.Sprintf("Rate limit reached for tool %q (%d calls per minute)", tool, tl.MaxPerMinute),
			}
		}
		if tl.MaxPerHour > 0 && len(recentHour) >= tl.MaxPerHour {
			return &LimitError{
				RuleName: "rate_budget_tool_limit",
				Message:  fmt.Sprintf("Rate limit reached for tool %q (%d calls per hour)", tool, tl.MaxPerHour),
			}
		}

		l.toolCalls[tool] = append(recentHour, now)
	}

	// Record global call
	l.globalCalls = append(l.globalCalls, now)
	l.totalCalls++
	return nil
}

// RecordTokens adds tokens to the session token count and checks against the budget.
func (l *Limiter) RecordTokens(tokens int64) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.totalTokens += tokens
	if l.cfg.MaxSessionTokens > 0 && l.totalTokens > l.cfg.MaxSessionTokens {
		return fmt.Errorf("session token budget exceeded: %d / %d tokens used", l.totalTokens, l.cfg.MaxSessionTokens)
	}
	return nil
}

// TotalCalls returns the total count of tool calls made in this session.
func (l *Limiter) TotalCalls() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.totalCalls
}

// TotalTokens returns the total count of tokens consumed in this session.
func (l *Limiter) TotalTokens() int64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.totalTokens
}
