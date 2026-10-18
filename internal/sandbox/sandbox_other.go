//go:build !darwin && !linux

package sandbox

import (
	"context"
	"os/exec"

	"github.com/smford/mcp-jail/internal/config"
)

// FallbackDriver is a passthrough driver for platforms where OS containerization is not yet supported.
type FallbackDriver struct{}

// NewDriver returns the fallback sandbox driver.
func NewDriver(cfg config.SandboxConfig) Driver {
	return &FallbackDriver{}
}

func (d *FallbackDriver) Name() string {
	return "unsupported-fallback"
}

func (d *FallbackDriver) IsAvailable() bool {
	return false
}

func (d *FallbackDriver) WrapCommand(ctx context.Context, cmd string, args []string, cfg config.SandboxConfig, allowedRoots []string) (*exec.Cmd, error) {
	return exec.CommandContext(ctx, cmd, args...), nil
}
