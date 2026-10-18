package scrubber

import (
	"strings"
	"testing"

	"github.com/smford/mcp-jail/internal/config"
)

func TestScrubberRedactions(t *testing.T) {
	cfg := config.ScrubberConfig{
		Enabled:        true,
		RedactPatterns: true,
		RedactEntropy:  true,
		CustomPatterns: []config.CustomPattern{
			{
				Name:  "CUSTOM_KEY",
				Regex: `mycorp_secret_[a-zA-Z0-9]{16}`,
			},
		},
	}

	sc, err := NewScrubber(cfg)
	if err != nil {
		t.Fatalf("failed to create scrubber: %v", err)
	}

	tests := []struct {
		name          string
		input         string
		expectedTag   string
		shouldContain string
	}{
		{
			name:        "AWS Access Key",
			input:       `Found credentials: {"access_key": "` + ("AKIA" + "IOSFODNN7EXAMPLE") + `"}`,
			expectedTag: "[REDACTED_BY_MCP_JAIL:AWS_KEY]",
		},
		{
			name:        "GitHub Classic PAT",
			input:       `Authorization: Bearer ` + ("ghp_" + "123456789012345678901234567890123456"),
			expectedTag: "[REDACTED_BY_MCP_JAIL:GITHUB_PAT]",
		},
		{
			name:        "GitHub Fine-grained PAT",
			input:       "github_pat_" + "11AAAAAAA0123456789012_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567",
			expectedTag: "[REDACTED_BY_MCP_JAIL:GITHUB_PAT]",
		},
		{
			name:        "Slack Token",
			input:       "token=" + ("xox" + "b-1234567890-1234567890123-abcdefghijklmnop"),
			expectedTag: "[REDACTED_BY_MCP_JAIL:SLACK_TOKEN]",
		},
		{
			name: "Private Key",
			input: "-----BEGIN " + "RSA PRIVATE KEY-----\n" +
				"MIIEowIBAAKCAQEA0Y1+\n" +
				"-----END " + "RSA PRIVATE KEY-----",
			expectedTag: "[REDACTED_BY_MCP_JAIL:PRIVATE_KEY]",
		},
		{
			name:        "Stripe Secret Key",
			input:       "sk_live_" + "51AbcdefghijklmnopqrstuvwxyzA1B2C3D4",
			expectedTag: "[REDACTED_BY_MCP_JAIL:STRIPE_KEY]",
		},
		{
			name:        "Custom Pattern",
			input:       `config loaded: mycorp_secret_abcdef1234567890`,
			expectedTag: "[REDACTED_BY_MCP_JAIL:CUSTOM_KEY]",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			output, count := sc.Scrub([]byte(tc.input))
			outStr := string(output)
			if count == 0 {
				t.Fatalf("expected at least 1 redaction, got 0")
			}
			if !strings.Contains(outStr, tc.expectedTag) {
				t.Errorf("expected output to contain %q, got: %s", tc.expectedTag, outStr)
			}
		})
	}
}

func TestScrubberDisabled(t *testing.T) {
	cfg := config.ScrubberConfig{
		Enabled: false,
	}
	sc, err := NewScrubber(cfg)
	if err != nil {
		t.Fatal(err)
	}

	input := "AKIAIOSFODNN7EXAMPLE"
	out, count := sc.Scrub([]byte(input))
	if count != 0 || string(out) != input {
		t.Errorf("scrubber should be no-op when disabled")
	}
}
