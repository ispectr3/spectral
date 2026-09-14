package detector

import (
	"strings"

	"github.com/ispectr3/spectral/pkg/entropy"
)

// Match represents a single detected secret finding.
type Match struct {
	RuleID      string  `json:"rule_id"`
	Provider    string  `json:"provider"`
	Description string  `json:"description"`
	Secret      string  `json:"secret"`
	Masked      string  `json:"masked"`
	LineNumber  int     `json:"line_number"`
	File        string  `json:"file"`
	Entropy     float64 `json:"entropy"`
	VerifyType  string  `json:"verify_type"`
	Status      string  `json:"status"` // "ACTIVE", "REVOKED", "UNVERIFIED"
}

// Engine encapsulates the rule evaluation logic.
type Engine struct {
	rules []Rule
}

// NewEngine initializes a detection engine with loaded rules.
func NewEngine() *Engine {
	return &Engine{
		rules: GetRules(),
	}
}

// ScanLine scans a single line of text from a given file and returns matches.
func (e *Engine) ScanLine(line string, lineNumber int, filePath string) []Match {
	var matches []Match

	for _, rule := range e.rules {
		// Fast path: check required substring if configured
		if rule.RequiredSubstr != "" && !strings.Contains(line, rule.RequiredSubstr) {
			continue
		}

		rawMatches := rule.Regex.FindAllString(line, -1)
		for _, raw := range rawMatches {
			// Skip placeholder/dummy strings
			if entropy.IsPlaceholder(raw) {
				continue
			}

			// Validate Shannon entropy threshold
			ent := entropy.Calculate(raw)
			if ent < rule.MinEntropy {
				continue
			}

			matches = append(matches, Match{
				RuleID:      rule.ID,
				Provider:    rule.Provider,
				Description: rule.Description,
				Secret:      raw,
				Masked:      MaskSecret(raw),
				LineNumber:  lineNumber,
				File:        filePath,
				Entropy:     ent,
				VerifyType:  rule.VerifyType,
				Status:      "UNVERIFIED",
			})
		}
	}

	return matches
}

// MaskSecret masks sensitive characters, retaining only prefix and suffix.
func MaskSecret(secret string) string {
	if len(secret) <= 8 {
		return "********"
	}
	prefixLen := 6
	suffixLen := 4
	if len(secret) < prefixLen+suffixLen {
		return secret[:2] + "****" + secret[len(secret)-2:]
	}
	return secret[:prefixLen] + strings.Repeat("*", len(secret)-prefixLen-suffixLen) + secret[len(secret)-suffixLen:]
}
