package learner

import (
	"strings"
	"testing"
)

func TestLearnerGenerateConfig(t *testing.T) {
	l := NewLearner()

	l.RecordToolCall("read_file", map[string]interface{}{"path": "src/main.go"})
	l.RecordToolCall("list_dir", map[string]interface{}{"dir": "src/"})
	l.RecordToolCall("read_file", map[string]interface{}{"path": "README.md"})
	l.AddTokens(5000)

	cfg := l.GenerateConfig()

	if len(cfg.Tools.Allowed) != 2 {
		t.Fatalf("expected 2 allowed tools, got %d", len(cfg.Tools.Allowed))
	}
	if cfg.Tools.Allowed[0] != "^list_dir$" && cfg.Tools.Allowed[1] != "^list_dir$" {
		t.Errorf("expected ^list_dir$ in allowed tools: %v", cfg.Tools.Allowed)
	}

	yamlStr, err := l.GenerateYAML()
	if err != nil {
		t.Fatalf("failed to generate YAML: %v", err)
	}
	if !strings.Contains(yamlStr, "^read_file$") {
		t.Errorf("expected yaml to contain ^read_file$: %s", yamlStr)
	}
}
