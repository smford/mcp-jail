package config

import (
	"testing"
)

func TestPresets(t *testing.T) {
	presets := ListPresets()
	if len(presets) == 0 {
		t.Fatalf("expected presets to be registered, got 0")
	}

	names := ListPresetNames()
	if len(names) != len(presets) {
		t.Fatalf("mismatched names count %d and presets count %d", len(names), len(presets))
	}

	expectedPresets := []string{"coding", "database", "default", "github", "homeassistant", "minimal"}
	for _, expected := range expectedPresets {
		p, err := GetPreset(expected)
		if err != nil {
			t.Errorf("failed to get preset %q: %v", expected, err)
			continue
		}
		if p.Name != expected {
			t.Errorf("expected preset name %q, got %q", expected, p.Name)
		}
		if len(p.Description) == 0 {
			t.Errorf("preset %q has empty description", expected)
		}
		if len(p.Summary) == 0 {
			t.Errorf("preset %q has empty summary", expected)
		}

		// Ensure YAML parses cleanly into valid Config
		cfg, err := ParseConfig([]byte(p.YAML))
		if err != nil {
			t.Errorf("preset %q failed to parse YAML: %v", expected, err)
			continue
		}
		if cfg == nil {
			t.Errorf("preset %q parsed to nil config", expected)
		}
	}

	// Test non-existent preset returns informative error
	_, err := GetPreset("nonexistent")
	if err == nil {
		t.Errorf("expected error for non-existent preset, got nil")
	}
}
