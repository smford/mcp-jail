//go:build linux

package sandbox

import (
	"context"
	"os/exec"
	"path/filepath"

	"github.com/smford/mcp-jail/internal/config"
)

// LinuxDriver implements sandboxing via Bubblewrap (bwrap).
type LinuxDriver struct {
	bwrapPath string
}

// NewDriver returns the Linux sandbox driver.
func NewDriver(cfg config.SandboxConfig) Driver {
	bin, err := exec.LookPath("bwrap")
	if err != nil {
		bin = ""
	}
	return &LinuxDriver{bwrapPath: bin}
}

func (d *LinuxDriver) Name() string {
	return "linux-bubblewrap"
}

func (d *LinuxDriver) IsAvailable() bool {
	return d.bwrapPath != ""
}

func (d *LinuxDriver) WrapCommand(ctx context.Context, cmd string, args []string, cfg config.SandboxConfig, allowedRoots []string) (*exec.Cmd, error) {
	if !d.IsAvailable() {
		// Bubblewrap not installed on host, fallback to plain exec
		return exec.CommandContext(ctx, cmd, args...), nil
	}

	var bwrapArgs []string
	if cfg.ReadOnlyRoot {
		bwrapArgs = append(bwrapArgs, "--ro-bind", "/", "/")
		for _, root := range allowedRoots {
			abs, err := filepath.Abs(root)
			if err == nil {
				bwrapArgs = append(bwrapArgs, "--bind", abs, abs)
			}
		}
	} else {
		bwrapArgs = append(bwrapArgs, "--bind", "/", "/")
	}

	bwrapArgs = append(bwrapArgs,
		"--dev", "/dev",
		"--proc", "/proc",
		"--tmpfs", "/tmp",
	)

	if cfg.IsolateNetwork {
		bwrapArgs = append(bwrapArgs, "--unshare-net")
	}

	bwrapArgs = append(bwrapArgs, "--", cmd)
	bwrapArgs = append(bwrapArgs, args...)

	return exec.CommandContext(ctx, d.bwrapPath, bwrapArgs...), nil
}
