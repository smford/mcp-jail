package vault

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"sync"
)

var vaultTokenRegex = regexp.MustCompile(`\{\{MCP_VAULT_TOKEN:([a-zA-Z0-9_-]+)\}\}`)

// Vault provides reversible, session-scoped secret tokenization.
type Vault struct {
	mu            sync.RWMutex
	tokenToSecret map[string]string
	secretToToken map[string]string
}

// NewVault constructs a new empty secret vault.
func NewVault() *Vault {
	return &Vault{
		tokenToSecret: make(map[string]string),
		secretToToken: make(map[string]string),
	}
}

// Tokenize stores a real secret and returns an opaque placeholder token.
func (v *Vault) Tokenize(secret string, tag string) string {
	v.mu.Lock()
	defer v.mu.Unlock()

	if token, exists := v.secretToToken[secret]; exists {
		return token
	}

	hash := sha256.Sum256([]byte(secret))
	tokenID := hex.EncodeToString(hash[:8])
	if tag != "" {
		tokenID = tag + "_" + tokenID
	}
	token := "{{MCP_VAULT_TOKEN:" + tokenID + "}}"

	v.secretToToken[secret] = token
	v.tokenToSecret[token] = secret
	return token
}

// Detokenize replaces all vault tokens in input with their original secret values.
func (v *Vault) Detokenize(input string) string {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if len(v.tokenToSecret) == 0 {
		return input
	}

	return vaultTokenRegex.ReplaceAllStringFunc(input, func(m string) string {
		if secret, ok := v.tokenToSecret[m]; ok {
			return secret
		}
		return m
	})
}

// Count returns the number of secrets managed in this vault session.
func (v *Vault) Count() int {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return len(v.secretToToken)
}
