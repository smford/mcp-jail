//go:build darwin

package sandbox

import (
	"strings"
	"testing"

	"github.com/smford/mcp-jail/internal/config"
)

func TestBuildProfile_Darwin(t *testing.T) {
	cfg := config.SandboxConfig{
		Enabled:        true,
		IsolateNetwork: true,
		ReadOnlyRoot:   true,
	}

	profile := BuildProfile(cfg, []string{"/test/root"})
	if !strings.Contains(profile, "(deny network*)") {
		t.Error("expected profile to deny network")
	}
	if !strings.Contains(profile, "(deny file-write*)") {
		t.Error("expected profile to deny file-write")
	}
	if !strings.Contains(profile, "/test/root") {
		t.Error("expected profile to include allowed root")
	}
}
