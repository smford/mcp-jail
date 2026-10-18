//go:build darwin

package sandbox

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/smford/mcp-jail/internal/config"
)

// DarwinDriver implements sandboxing via macOS sandbox-exec (Seatbelt).
type DarwinDriver struct {
	binaryPath string
}

// NewDriver returns the OS-specific sandbox driver.
func NewDriver(cfg config.SandboxConfig) Driver {
	bin, err := exec.LookPath("sandbox-exec")
	if err != nil {
		bin = "/usr/bin/sandbox-exec"
	}
	return &DarwinDriver{binaryPath: bin}
}

func (d *DarwinDriver) Name() string {
	return "macos-sandbox-exec"
}

func (d *DarwinDriver) IsAvailable() bool {
	if _, err := os.Stat(d.binaryPath); err == nil {
		return true
	}
	return false
}

// BuildProfile generates a Seatbelt S-expression profile.
func BuildProfile(cfg config.SandboxConfig, allowedRoots []string) string {
	var sb strings.Builder
	sb.WriteString("(version 1)\n")
	sb.WriteString("(allow default)\n") // Default allow, selectively restrict

	if cfg.IsolateNetwork {
		sb.WriteString("(deny network*)\n")
	}

	if cfg.ReadOnlyRoot && len(allowedRoots) > 0 {
		sb.WriteString("(deny file-write*)\n")
		for _, root := range allowedRoots {
			abs, err := filepath.Abs(root)
			if err == nil {
				sb.WriteString(fmt.Sprintf("(allow file-write* (subpath %q))\n", abs))
			}
		}
		// Allow temp directories
		sb.WriteString("(allow file-write* (subpath \"/tmp\"))\n")
		sb.WriteString("(allow file-write* (subpath \"/private/tmp\"))\n")
		sb.WriteString("(allow file-write* (subpath \"/dev/null\"))\n")
		sb.WriteString("(allow file-write* (subpath \"/dev/tty\"))\n")
	}

	return sb.String()
}

func (d *DarwinDriver) WrapCommand(ctx context.Context, cmd string, args []string, cfg config.SandboxConfig, allowedRoots []string) (*exec.Cmd, error) {
	if !d.IsAvailable() || (!cfg.IsolateNetwork && !cfg.ReadOnlyRoot) {
		// Passthrough if sandbox-exec is missing or no restrictions requested
		return exec.CommandContext(ctx, cmd, args...), nil
	}

	profile := BuildProfile(cfg, allowedRoots)
	var newArgs []string
	newArgs = append(newArgs, "-p", profile, cmd)
	newArgs = append(newArgs, args...)

	return exec.CommandContext(ctx, d.binaryPath, newArgs...), nil
}
