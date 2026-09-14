package output

import (
	"encoding/json"
	"io"
	"os"

	"github.com/ispectr3/spectral/pkg/detector"
)

type SarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SarifRun `json:"runs"`
}

type SarifRun struct {
	Tool    SarifTool     `json:"tool"`
	Results []SarifResult `json:"results"`
}

type SarifTool struct {
	Driver SarifDriver `json:"driver"`
}

type SarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationUri string      `json:"informationUri"`
	Rules          []SarifRule `json:"rules"`
}

type SarifRule struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	ShortDescription struct {
		Text string `json:"text"`
	} `json:"shortDescription"`
}

type SarifResult struct {
	RuleID    string `json:"ruleId"`
	Level     string `json:"level"`
	Message   struct {
		Text string `json:"text"`
	} `json:"message"`
	Locations []SarifLocation `json:"locations"`
}

type SarifLocation struct {
	PhysicalLocation SarifPhysicalLocation `json:"physicalLocation"`
}

type SarifPhysicalLocation struct {
	ArtifactLocation struct {
		Uri string `json:"uri"`
	} `json:"artifactLocation"`
	Region struct {
		StartLine int `json:"startLine"`
	} `json:"region"`
}

// RenderSARIF exports matches into a SARIF 2.1.0 document.
func RenderSARIF(w io.Writer, matches []detector.Match) error {
	ruleMap := make(map[string]bool)
	var sarifRules []SarifRule

	for _, m := range matches {
		if !ruleMap[m.RuleID] {
			ruleMap[m.RuleID] = true
			var r SarifRule
			r.ID = m.RuleID
			r.Name = m.Provider + " Secret Leak"
			r.ShortDescription.Text = m.Description
			sarifRules = append(sarifRules, r)
		}
	}

	var results []SarifResult
	for _, m := range matches {
		level := "warning"
		if m.Status == "ACTIVE" {
			level = "error"
		}

		var res SarifResult
		res.RuleID = m.RuleID
		res.Level = level
		res.Message.Text = "Exposed " + m.Provider + " secret detected: " + m.Masked

		var loc SarifLocation
		loc.PhysicalLocation.ArtifactLocation.Uri = m.File
		loc.PhysicalLocation.Region.StartLine = m.LineNumber
		res.Locations = []SarifLocation{loc}

		results = append(results, res)
	}

	log := SarifLog{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []SarifRun{
			{
				Tool: SarifTool{
					Driver: SarifDriver{
						Name:           "Spectral",
						Version:        "1.0.0",
						InformationUri: "https://github.com/ispectr3/spectral",
						Rules:          sarifRules,
					},
				},
				Results: results,
			},
		},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

// SaveSARIFToFile writes SARIF output directly to a file.
func SaveSARIFToFile(filePath string, matches []detector.Match) error {
	f, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer f.Close()
	return RenderSARIF(f, matches)
}
