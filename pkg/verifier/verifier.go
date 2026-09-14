package verifier

import (
	"context"
	"net/http"
	"time"

	"github.com/ispectr3/spectral/pkg/detector"
)

// Verifier executes live verification probes against provider APIs.
type Verifier struct {
	client *http.Client
}

// NewVerifier initializes a Verifier with a conservative network timeout.
func NewVerifier(timeout time.Duration) *Verifier {
	if timeout <= 0 {
		timeout = 4 * time.Second
	}
	return &Verifier{
		client: &http.Client{
			Timeout: timeout,
		},
	}
}

// SetClient allows overriding the HTTP client for testing.
func (v *Verifier) SetClient(c *http.Client) {
	v.client = c
}

// Verify checks the liveness of a detected secret against its provider.
func (v *Verifier) Verify(ctx context.Context, match *detector.Match) string {
	switch match.VerifyType {
	case "openai":
		return v.verifyOpenAI(ctx, match.Secret)
	case "anthropic":
		return v.verifyAnthropic(ctx, match.Secret)
	case "stripe":
		return v.verifyStripe(ctx, match.Secret)
	case "github":
		return v.verifyGitHub(ctx, match.Secret)
	case "huggingface":
		return v.verifyHuggingFace(ctx, match.Secret)
	default:
		return "UNVERIFIED"
	}
}

func (v *Verifier) verifyOpenAI(ctx context.Context, key string) string {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.openai.com/v1/models", nil)
	if err != nil {
		return "ERROR"
	}
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("User-Agent", "Spectral-Security-Audit/1.0")

	resp, err := v.client.Do(req)
	if err != nil {
		return "NETWORK_ERROR"
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		return "ACTIVE"
	case http.StatusUnauthorized:
		return "REVOKED"
	case http.StatusTooManyRequests:
		return "ACTIVE (RATE_LIMITED)"
	default:
		return "UNKNOWN"
	}
}

func (v *Verifier) verifyAnthropic(ctx context.Context, key string) string {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.anthropic.com/v1/models", nil)
	if err != nil {
		return "ERROR"
	}
	req.Header.Set("x-api-key", key)
	req.Header.Set("anthropic-version", "2023-06-01")
	req.Header.Set("User-Agent", "Spectral-Security-Audit/1.0")

	resp, err := v.client.Do(req)
	if err != nil {
		return "NETWORK_ERROR"
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		return "ACTIVE"
	case http.StatusUnauthorized, http.StatusForbidden:
		return "REVOKED"
	default:
		return "UNKNOWN"
	}
}

func (v *Verifier) verifyStripe(ctx context.Context, key string) string {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.stripe.com/v1/charges?limit=1", nil)
	if err != nil {
		return "ERROR"
	}
	req.SetBasicAuth(key, "")
	req.Header.Set("User-Agent", "Spectral-Security-Audit/1.0")

	resp, err := v.client.Do(req)
	if err != nil {
		return "NETWORK_ERROR"
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		return "ACTIVE"
	case http.StatusUnauthorized:
		return "REVOKED"
	default:
		return "UNKNOWN"
	}
}

func (v *Verifier) verifyGitHub(ctx context.Context, key string) string {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/user", nil)
	if err != nil {
		return "ERROR"
	}
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("User-Agent", "Spectral-Security-Audit/1.0")

	resp, err := v.client.Do(req)
	if err != nil {
		return "NETWORK_ERROR"
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		return "ACTIVE"
	case http.StatusUnauthorized:
		return "REVOKED"
	default:
		return "UNKNOWN"
	}
}

func (v *Verifier) verifyHuggingFace(ctx context.Context, key string) string {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://huggingface.co/api/whoami-v2", nil)
	if err != nil {
		return "ERROR"
	}
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("User-Agent", "Spectral-Security-Audit/1.0")

	resp, err := v.client.Do(req)
	if err != nil {
		return "NETWORK_ERROR"
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		return "ACTIVE"
	case http.StatusUnauthorized:
		return "REVOKED"
	default:
		return "UNKNOWN"
	}
}
