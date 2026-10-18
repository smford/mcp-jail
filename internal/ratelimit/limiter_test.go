package ratelimit

import (
	"testing"

	"github.com/smford/mcp-jail/internal/config"
)

func TestLimiter_PerToolLimits(t *testing.T) {
	cfg := config.LimitsConfig{
		MaxToolCallsPerMinute:   10,
		MaxTotalCallsPerSession: 20,
		ToolLimits: []config.ToolRateLimitConfig{
			{
				Tool:         "expensive_query",
				MaxPerMinute: 2,
				MaxPerHour:   5,
			},
		},
	}

	l := NewLimiter(cfg)

	// First two calls should succeed
	if err := l.RecordToolCall("expensive_query"); err != nil {
		t.Fatalf("unexpected error on 1st call: %v", err)
	}
	if err := l.RecordToolCall("expensive_query"); err != nil {
		t.Fatalf("unexpected error on 2nd call: %v", err)
	}

	// 3rd call within the minute should fail
	if err := l.RecordToolCall("expensive_query"); err == nil {
		t.Fatalf("expected rate limit error on 3rd call, got nil")
	}

	// Other tools should still succeed up to global limit
	if err := l.RecordToolCall("read_file"); err != nil {
		t.Fatalf("unexpected error on read_file call: %v", err)
	}
}

func TestLimiter_TotalSessionLimit(t *testing.T) {
	cfg := config.LimitsConfig{
		MaxTotalCallsPerSession: 3,
	}

	l := NewLimiter(cfg)
	for i := 0; i < 3; i++ {
		if err := l.RecordToolCall("tool"); err != nil {
			t.Fatalf("unexpected error on call %d: %v", i+1, err)
		}
	}

	if err := l.RecordToolCall("tool"); err == nil {
		t.Fatalf("expected session limit error on 4th call, got nil")
	}
}

func TestLimiter_TokenBudget(t *testing.T) {
	cfg := config.LimitsConfig{
		MaxSessionTokens: 1000,
	}

	l := NewLimiter(cfg)
	if err := l.RecordTokens(600); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if l.TotalTokens() != 600 {
		t.Fatalf("expected 600 tokens, got %d", l.TotalTokens())
	}

	if err := l.RecordTokens(500); err == nil {
		t.Fatalf("expected token budget error, got nil")
	}
}
