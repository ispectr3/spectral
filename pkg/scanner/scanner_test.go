package scanner

import (
	"fmt"
	"strings"
	"testing"

	"github.com/ispectr3/spectral/pkg/detector"
)

func TestScanner_ScanReader(t *testing.T) {
	engine := detector.NewEngine()
	sc := NewScanner(engine, Config{})

	stripeToken := fmt.Sprintf("sk_%s_%s", "live", "51MzQ34Bv98769874ZaBcDeFgHiJkLmNoPqRsTuVwXyZ")
	githubToken := fmt.Sprintf("gh%s_%s", "p", "mK9vL3xP8qW2zR5tY7uI4oP1aS6dF8gH0jK2")
	dummyToken := fmt.Sprintf("sk-%s-%s_%s", "proj", "YOUR_KEY_HERE", "T3BlbkFJ_dummy_token")

	input := fmt.Sprintf(`
# Configuration sample
DATABASE_URL=postgres://user:pass@localhost:5432/db
STRIPE_KEY=%s
GITHUB_TOKEN=%s
DUMMY=%s
`, stripeToken, githubToken, dummyToken)

	matches, err := sc.ScanReader(strings.NewReader(input), "memory.env")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(matches) != 2 {
		t.Fatalf("expected 2 matches, got %d", len(matches))
	}

	foundStripe := false
	foundGitHub := false
	for _, m := range matches {
		if m.RuleID == "stripe-live-secret-key" {
			foundStripe = true
		}
		if m.RuleID == "github-pat-classic" {
			foundGitHub = true
		}
	}

	if !foundStripe || !foundGitHub {
		t.Errorf("did not find expected secrets (Stripe: %v, GitHub: %v)", foundStripe, foundGitHub)
	}
}
