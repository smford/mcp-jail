package sandbox

import (
	"context"
	"testing"

	"github.com/smford/mcp-jail/internal/config"
)

func TestDriver_WrapCommand(t *testing.T) {
	cfg := config.SandboxConfig{
		Enabled:        true,
		IsolateNetwork: true,
		ReadOnlyRoot:   true,
	}

	driver := NewDriver(cfg)
	if driver == nil {
		t.Fatal("expected driver not nil")
	}

	ctx := context.Background()
	cmd, err := driver.WrapCommand(ctx, "echo", []string{"hello"}, cfg, []string{"/tmp/test"})
	if err != nil {
		t.Fatalf("unexpected error wrapping command: %v", err)
	}
	if cmd == nil {
		t.Fatal("expected wrapped command not nil")
	}
}
