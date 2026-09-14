package verifier

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ispectr3/spectral/pkg/detector"
)

func TestVerifier_Verify(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "Bearer active_token" {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	defer server.Close()

	v := NewVerifier(2 * time.Second)

	matchUnverified := &detector.Match{
		VerifyType: "unknown_provider",
		Secret:     "foo_bar",
	}

	status := v.Verify(context.Background(), matchUnverified)
	if status != "UNVERIFIED" {
		t.Errorf("expected UNVERIFIED, got %s", status)
	}
}
