package entropy

import (
	"math"
	"strings"
)

// Common placeholder substrings that identify non-production tokens.
var placeholderTokens = []string{
	"your_key", "your-key", "your_token", "your-token",
	"placeholder", "dummy_key", "fake_key", "test_key",
	"xxxxxxxx", "00000000", "insert_here",
}

// Calculate computes the Shannon entropy of a given string in bits per character.
func Calculate(s string) float64 {
	if len(s) == 0 {
		return 0.0
	}

	freq := make(map[rune]float64)
	for _, r := range s {
		freq[r]++
	}

	total := float64(len(s))
	var ent float64
	for _, count := range freq {
		p := count / total
		ent -= p * math.Log2(p)
	}

	return ent
}

// IsHighEntropy evaluates whether the candidate string exceeds the minimum entropy threshold.
func IsHighEntropy(s string, threshold float64) bool {
	return Calculate(s) >= threshold
}

// IsPlaceholder checks if the secret is an obvious dummy, test, or placeholder string.
func IsPlaceholder(s string) bool {
	lower := strings.ToLower(s)
	for _, p := range placeholderTokens {
		if strings.Contains(lower, p) {
			return true
		}
	}

	// Reject repeating characters (e.g. "aaaaa", "11111")
	if len(s) >= 8 {
		allSame := true
		first := s[0]
		for i := 1; i < len(s); i++ {
			if s[i] != first {
				allSame = false
				break
			}
		}
		if allSame {
			return true
		}
	}

	return false
}
