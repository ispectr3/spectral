package output

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/ispectr3/spectral/pkg/detector"
)

func TestRenderSARIF(t *testing.T) {
	fakeToken := fmt.Sprintf("sk-%s-%s%s%s", "proj", "abc123", "T3BlbkFJ", "xyz987")
	matches := []detector.Match{
		{
			RuleID:      "openai-project-key",
			Provider:    "OpenAI",
			Description: "OpenAI Project Key",
			Secret:      fakeToken,
			Masked:      "sk-proj-***987",
			LineNumber:  42,
			File:        ".env",
			Status:      "ACTIVE",
		},
	}

	var buf bytes.Buffer
	err := RenderSARIF(&buf, matches)
	if err != nil {
		t.Fatalf("RenderSARIF failed: %v", err)
	}

	var log SarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("Failed unmarshaling SARIF output: %v", err)
	}

	if log.Version != "2.1.0" {
		t.Errorf("expected version 2.1.0, got %s", log.Version)
	}

	if len(log.Runs) == 0 || len(log.Runs[0].Results) != 1 {
		t.Fatalf("expected 1 run with 1 result, got %v", log.Runs)
	}

	if log.Runs[0].Results[0].Level != "error" {
		t.Errorf("expected level error for ACTIVE status, got %s", log.Runs[0].Results[0].Level)
	}
}
