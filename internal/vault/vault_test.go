package vault

import (
	"strings"
	"testing"
)

func TestVaultTokenizeAndDetokenize(t *testing.T) {
	v := NewVault()

	secret1 := "gh" + "p_1234567890abcdef1234567890abcdef1234"
	secret2 := "sk" + "_live_1234567890abcdef12345678"

	tok1 := v.Tokenize(secret1, "GITHUB")
	tok2 := v.Tokenize(secret2, "STRIPE")

	if !strings.HasPrefix(tok1, "{{MCP_VAULT_TOKEN:GITHUB_") {
		t.Fatalf("unexpected token format: %s", tok1)
	}

	if v.Count() != 2 {
		t.Errorf("expected count 2, got %d", v.Count())
	}

	// Repeated tokenization returns same token
	tok1Repeat := v.Tokenize(secret1, "GITHUB")
	if tok1Repeat != tok1 {
		t.Errorf("expected idempotent tokenization: %s != %s", tok1Repeat, tok1)
	}

	// Detokenize payload
	payload := `{"token": "` + tok1 + `", "key": "` + tok2 + `"}`
	detokenized := v.Detokenize(payload)

	if !strings.Contains(detokenized, secret1) {
		t.Errorf("expected payload to contain %s, got %s", secret1, detokenized)
	}
	if !strings.Contains(detokenized, secret2) {
		t.Errorf("expected payload to contain %s, got %s", secret2, detokenized)
	}
}
