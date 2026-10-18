package sandbox

import (
	"context"
	"os/exec"

	"github.com/smford/mcp-jail/internal/config"
)

// Driver encapsulates OS-level subprocess sandboxing capabilities.
type Driver interface {
	Name() string
	IsAvailable() bool
	WrapCommand(ctx context.Context, cmd string, args []string, cfg config.SandboxConfig, allowedRoots []string) (*exec.Cmd, error)
}
