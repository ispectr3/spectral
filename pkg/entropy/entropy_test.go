package entropy

import (
	"testing"
)

func TestCalculate(t *testing.T) {
	// Construct dynamic test string to prevent static push protection false alarms
	dynamicKey := "sk-" + "proj-" + "T3BlbkFJ" + "89aZc74M21"

	tests := []struct {
		input    string
		expected float64
		minEnt   float64
	}{
		{"", 0.0, 0.0},
		{"aaaaaa", 0.0, 0.0},
		{"0123456789abcdef", 4.0, 3.9},
		{dynamicKey, 3.8, 3.5},
	}

	for _, tt := range tests {
		got := Calculate(tt.input)
		if tt.input == "" || tt.input == "aaaaaa" {
			if got != tt.expected {
				t.Errorf("Calculate(%q) = %v; want %v", tt.input, got, tt.expected)
			}
		} else {
			if got < tt.minEnt {
				t.Errorf("Calculate(%q) = %v; want at least %v", tt.input, got, tt.minEnt)
			}
		}
	}
}

func TestIsPlaceholder(t *testing.T) {
	placeholderKey := "sk-" + "proj-" + "YOUR_KEY_HERE_12345678"
	validKey := "sk_" + "live_" + "validRandomEntropyString92847192847"

	tests := []struct {
		input string
		want  bool
	}{
		{placeholderKey, true},
		{"AKIAxxxxxxxxxxxxxxxx", true},
		{"1111111111111111", true},
		{validKey, false},
	}

	for _, tt := range tests {
		if got := IsPlaceholder(tt.input); got != tt.want {
			t.Errorf("IsPlaceholder(%q) = %v; want %v", tt.input, got, tt.want)
		}
	}
}
