package policy

import (
	"encoding/json"
	"fmt"
	"regexp"
)

// SamplingMessage represents a message inside an MCP sampling/createMessage request.
type SamplingMessage struct {
	Role    string                 `json:"role"`
	Content map[string]interface{} `json:"content"`
}

type samplingParams struct {
	Messages       []SamplingMessage `json:"messages"`
	SystemPrompt   string            `json:"systemPrompt"`
	IncludeContext string            `json:"includeContext"`
}

var injectionPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\bignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions\b`),
	regexp.MustCompile(`(?i)\bsystem\s+prompt\s+override\b`),
	regexp.MustCompile(`(?i)\bdisregard\s+(?:all\s+)?guidelines\b`),
	regexp.MustCompile(`(?i)\byou\s+are\s+now\s+(?:in\s+developer\s+mode|unrestricted|DAN)\b`),
	regexp.MustCompile(`(?i)\b(?:print|reveal|exfiltrate|send)\s+(?:all\s+)?(?:env|environment|passwords|secrets|private\s+keys|tokens)\b`),
	regexp.MustCompile(`(?i)\bbypass\s+(?:all\s+)?(?:security|sandbox|safeguards|restrictions)\b`),
}

// InspectSamplingMessage inspects params of an MCP sampling/createMessage call for prompt injection.
func (e *Engine) InspectSamplingMessage(rawParams json.RawMessage) *Violation {
	if !e.cfg.Sampling.Enabled || !e.cfg.Sampling.BlockInjections || len(rawParams) == 0 {
		return nil
	}

	var params samplingParams
	if err := json.Unmarshal(rawParams, &params); err != nil {
		return nil
	}

	// Check systemPrompt
	if params.SystemPrompt != "" {
		if v := checkTextForInjection(params.SystemPrompt, "systemPrompt"); v != nil {
			return v
		}
	}

	// Check message contents
	for i, msg := range params.Messages {
		if text, ok := msg.Content["text"].(string); ok && text != "" {
			field := fmt.Sprintf("messages[%d].content.text", i)
			if v := checkTextForInjection(text, field); v != nil {
				return v
			}
		}
	}

	return nil
}

func checkTextForInjection(text, location string) *Violation {
	for _, re := range injectionPatterns {
		if loc := re.FindString(text); loc != "" {
			return &Violation{
				RuleName: "prompt_injection_guard",
				Reason: fmt.Sprintf("Suspicious prompt injection payload detected in %s: %q",
					location, loc),
			}
		}
	}
	return nil
}
