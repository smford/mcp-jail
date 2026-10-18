package policy

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/smford/mcp-jail/internal/config"
)

type mockApprovalHandler struct {
	approve bool
}

func (m *mockApprovalHandler) RequestApproval(ctx context.Context, toolName string, details string) (bool, error) {
	return m.approve, nil
}

func TestApprovalPolicy(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Approval.Enabled = true
	cfg.Approval.AskTools = []string{"^git_commit$"}
	cfg.Approval.AskCommands = []string{`git\s+push`}

	engine, err := NewEngine(cfg, ".")
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	// 1. Approval Denied
	engine.SetApprovalHandler(&mockApprovalHandler{approve: false})
	v := engine.EvaluateToolCall("git_commit", map[string]interface{}{"message": "feat: test"})
	if v == nil {
		t.Fatalf("expected violation for unapproved tool call, got nil")
	}
	if v.RuleName != "human_approval_denied" {
		t.Errorf("expected rule human_approval_denied, got %s", v.RuleName)
	}

	// 2. Approval Granted
	engine.SetApprovalHandler(&mockApprovalHandler{approve: true})
	v = engine.EvaluateToolCall("git_commit", map[string]interface{}{"message": "feat: test"})
	if v != nil {
		t.Fatalf("expected tool call to be approved, got violation: %v", v)
	}

	// 3. Command requiring approval
	engine.SetApprovalHandler(&mockApprovalHandler{approve: false})
	v = engine.EvaluateToolCall("bash", map[string]interface{}{"command": "git push origin main"})
	if v == nil {
		t.Fatalf("expected violation for unapproved command, got nil")
	}

	engine.SetApprovalHandler(&mockApprovalHandler{approve: true})
	v = engine.EvaluateToolCall("bash", map[string]interface{}{"command": "git push origin main"})
	if v != nil {
		t.Fatalf("expected command to be approved, got violation: %v", v)
	}
}

func TestConsoleApprovalHandler(t *testing.T) {
	inBuf := strings.NewReader("y\n")
	outBuf := &bytes.Buffer{}

	handler := NewConsoleApprovalHandler(5, false)
	handler.SetTTY(inBuf, outBuf)

	approved, err := handler.RequestApproval(context.Background(), "git_commit", "commit to main")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !approved {
		t.Fatalf("expected approval to be true when answering 'y'")
	}

	// Test NonInteractive auto-denial
	nonInteractiveHandler := NewConsoleApprovalHandler(5, true)
	approved, err = nonInteractiveHandler.RequestApproval(context.Background(), "git_commit", "")
	if approved {
		t.Fatalf("expected nonInteractiveHandler to reject")
	}
	if err == nil {
		t.Fatalf("expected nonInteractiveHandler to return error")
	}
}
