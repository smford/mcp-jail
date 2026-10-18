package scrubber

import (
	"fmt"
	"math"
	"regexp"
	"strings"

	"github.com/smford/mcp-jail/internal/config"
)

type patternRule struct {
	Name    string
	Regex   *regexp.Regexp
	Tag     string
	Replace func([]string) string // optional custom replacer
}

// Scrubber redacts sensitive credentials and high-entropy secrets from text.
type Scrubber struct {
	cfg           config.ScrubberConfig
	compiledRules []patternRule
}

// NewScrubber creates a new Scrubber configured with known patterns and custom rules.
func NewScrubber(cfg config.ScrubberConfig) (*Scrubber, error) {
	s := &Scrubber{
		cfg: cfg,
	}

	if cfg.RedactPatterns {
		// Standard credential patterns
		s.compiledRules = append(s.compiledRules, []patternRule{
			{
				Name:  "AWS Access Key ID",
				Regex: regexp.MustCompile(`\b(AKIA[0-9A-Z]{16})\b`),
				Tag:   "AWS_KEY",
			},
			{
				Name:  "AWS Secret Key Assignment",
				Regex: regexp.MustCompile(`(?i)(aws_secret_access_key|aws_secret_key|secret_key)\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})["']?`),
				Tag:   "AWS_SECRET",
			},
			{
				Name:  "GitHub Classic PAT",
				Regex: regexp.MustCompile(`\b(ghp_[a-zA-Z0-9]{36})\b`),
				Tag:   "GITHUB_PAT",
			},
			{
				Name:  "GitHub Fine-grained PAT",
				Regex: regexp.MustCompile(`\b(github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59})\b`),
				Tag:   "GITHUB_PAT",
			},
			{
				Name:  "GitHub OAuth / App Token",
				Regex: regexp.MustCompile(`\b(gh[osru]_[a-zA-Z0-9]{36})\b`),
				Tag:   "GITHUB_TOKEN",
			},
			{
				Name:  "Slack Token",
				Regex: regexp.MustCompile(`\b(xox[baprs]-[0-9a-zA-Z]{10,48})\b`),
				Tag:   "SLACK_TOKEN",
			},
			{
				Name:  "Private Key Block",
				Regex: regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----`),
				Tag:   "PRIVATE_KEY",
			},
			{
				Name:  "Stripe Key",
				Regex: regexp.MustCompile(`\b((?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,99})\b`),
				Tag:   "STRIPE_KEY",
			},
			{
				Name:  "Generic API Key / Secret Assignment",
				Regex: regexp.MustCompile(`(?i)(api[_-]?key|apikey|secret[_-]?key|auth[_-]?token|access[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9_\-\.]{16,128})["']?`),
				Tag:   "API_KEY",
			},
			{
				Name:  "JWT Token",
				Regex: regexp.MustCompile(`\b(ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b`),
				Tag:   "JWT",
			},
		}...)
	}

	// Compile custom patterns
	for _, cp := range cfg.CustomPatterns {
		re, err := regexp.Compile(cp.Regex)
		if err != nil {
			return nil, fmt.Errorf("invalid custom pattern %q (%s): %w", cp.Name, cp.Regex, err)
		}
		s.compiledRules = append(s.compiledRules, patternRule{
			Name:  cp.Name,
			Regex: re,
			Tag:   strings.ToUpper(strings.ReplaceAll(cp.Name, " ", "_")),
		})
	}

	return s, nil
}

// Scrub scans content, replaces matches with [REDACTED_BY_MCP_JAIL:<TYPE>],
// and returns the scrubbed content and count of redactions.
func (s *Scrubber) Scrub(input []byte) ([]byte, int) {
	if !s.cfg.Enabled || len(input) == 0 {
		return input, 0
	}

	text := string(input)
	redactionCount := 0

	// 1. Pattern based redactions
	for _, rule := range s.compiledRules {
		replacementTag := fmt.Sprintf("[REDACTED_BY_MCP_JAIL:%s]", rule.Tag)

		// Check if matches have capture groups
		matches := rule.Regex.FindAllStringSubmatchIndex(text, -1)
		if len(matches) == 0 {
			continue
		}

		// Replace in reverse order so string offsets remain valid
		for i := len(matches) - 1; i >= 0; i-- {
			match := matches[i]
			redactionCount++

			// If the pattern has 2 capture groups (e.g. key = value), redact only the value group
			if len(match) >= 6 && match[4] >= 0 && match[5] >= 0 {
				valStart := match[4]
				valEnd := match[5]
				text = text[:valStart] + replacementTag + text[valEnd:]
			} else if len(match) >= 4 && match[2] >= 0 && match[3] >= 0 {
				// Single capture group (the secret itself)
				valStart := match[2]
				valEnd := match[3]
				text = text[:valStart] + replacementTag + text[valEnd:]
			} else {
				// Full match
				text = text[:match[0]] + replacementTag + text[match[1]:]
			}
		}
	}

	// 2. High entropy token detection (if enabled)
	if s.cfg.RedactEntropy {
		text, redactionCount = s.scrubHighEntropy(text, redactionCount)
	}

	return []byte(text), redactionCount
}

var tokenSplitRegex = regexp.MustCompile(`[a-zA-Z0-9_\-\.]{24,}`)

func (s *Scrubber) scrubHighEntropy(text string, count int) (string, int) {
	// Look for long contiguous alphanumeric tokens that might be uncaptured high-entropy keys
	matches := tokenSplitRegex.FindAllStringIndex(text, -1)
	if len(matches) == 0 {
		return text, count
	}

	for i := len(matches) - 1; i >= 0; i-- {
		start, end := matches[i][0], matches[i][1]
		token := text[start:end]

		// Skip if already redacted or if all same char
		if strings.Contains(token, "REDACTED_BY_MCP_JAIL") {
			continue
		}

		entropy := calculateShannonEntropy(token)
		// Threshold: Shannon entropy > 4.6 for random strings (e.g. Base64 / Hex secrets)
		// and length >= 28 chars
		if len(token) >= 28 && entropy >= 4.6 {
			// Avoid pure numbers or repeated structures
			tag := "[REDACTED_BY_MCP_JAIL:HIGH_ENTROPY]"
			text = text[:start] + tag + text[end:]
			count++
		}
	}

	return text, count
}

func calculateShannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[rune]float64)
	for _, r := range s {
		freq[r]++
	}
	length := float64(len(s))
	entropy := 0.0
	for _, count := range freq {
		p := count / length
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}
