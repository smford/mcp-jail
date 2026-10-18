package policy

import (
	"testing"

	"github.com/smford/mcp-jail/internal/config"
)

func TestEvaluateResource(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Resources = config.ResourcesConfig{
		Enabled:     true,
		AllowedURIs: []string{"postgres://readonly@localhost/**", "file:///allowed/**"},
		DeniedURIs:  []string{"file:///etc/**", "**/.env*"},
	}

	engine, err := NewEngine(cfg, ".")
	if err != nil {
		t.Fatalf("failed to init engine: %v", err)
	}

	// Allowed URI
	if v := engine.EvaluateResource("postgres://readonly@localhost/mydb"); v != nil {
		t.Errorf("expected allowed resource, got violation: %s", v.Reason)
	}

	// Denied URI (explicit pattern)
	if v := engine.EvaluateResource("file:///etc/shadow"); v == nil {
		t.Error("expected violation for file:///etc/shadow, got nil")
	}

	// Denied URI (.env)
	if v := engine.EvaluateResource("file:///allowed/.env"); v == nil {
		t.Error("expected violation for file:///allowed/.env, got nil")
	}

	// Not in allowed list
	if v := engine.EvaluateResource("http://remote.host/api"); v == nil {
		t.Error("expected violation for http://remote.host/api, got nil")
	}
}

func TestEvaluatePrompt(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Prompts = config.PromptsConfig{
		Enabled: true,
		Allowed: []string{"^code_review$", "^explain_.*"},
		Denied:  []string{"^drop_all$"},
	}

	engine, err := NewEngine(cfg, ".")
	if err != nil {
		t.Fatalf("failed to init engine: %v", err)
	}

	// Allowed prompt
	if v := engine.EvaluatePrompt("code_review"); v != nil {
		t.Errorf("expected allowed prompt, got violation: %s", v.Reason)
	}
	if v := engine.EvaluatePrompt("explain_error"); v != nil {
		t.Errorf("expected allowed prompt, got violation: %s", v.Reason)
	}

	// Denied prompt
	if v := engine.EvaluatePrompt("drop_all"); v == nil {
		t.Error("expected violation for drop_all, got nil")
	}

	// Not in allowed list
	if v := engine.EvaluatePrompt("delete_prod"); v == nil {
		t.Error("expected violation for delete_prod, got nil")
	}
}
