package output

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/ispectr3/spectral/pkg/detector"
)

// ANSI color codes for terminal rendering.
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorCyan   = "\033[36m"
	colorBold   = "\033[1m"
)

// PrintBanner outputs the Spectral ASCII banner.
func PrintBanner(w io.Writer) {
	banner := `
  ____  ____  _____ ____ _____ ____     _     _     
 / ___||  _ \| ____/ ___|_   _|  _ \   / \   | |    
 \___ \| |_) |  _|| |     | | | |_) | / _ \  | |    
  ___) |  __/| |__| |___  | | |  _ < / ___ \ | |___ 
 |____/|_|   |_____\____| |_| |_| \_/_/   \_\|_____|
`
	fmt.Fprintf(w, "%s%s%s", colorCyan, banner, colorReset)
	fmt.Fprintf(w, " %sSpectral v1.0.0 - High-Performance Secret & Key Hunter%s\n", colorBold, colorReset)
	fmt.Fprintf(w, " Maintainer: @ispectr3 | Engine: Go Concurrent Pipeline\n\n")
}

// RenderTable writes findings to stdout in formatted terminal output.
func RenderTable(w io.Writer, matches []detector.Match) {
	if len(matches) == 0 {
		fmt.Fprintf(w, "%s[+] No leaked secrets detected.%s\n", colorGreen, colorReset)
		return
	}

	fmt.Fprintf(w, "%s[!] FOUND %d POTENTIAL LEAKED SECRETS:%s\n\n", colorRed, len(matches), colorReset)

	for i, m := range matches {
		statusColor := colorCyan
		switch m.Status {
		case "ACTIVE":
			statusColor = colorRed + colorBold
		case "REVOKED":
			statusColor = colorYellow
		case "UNVERIFIED":
			statusColor = colorBlue
		}

		fmt.Fprintf(w, " %s[%02d]%s %s%-12s%s | %s%-32s%s | Ent: %.2f | %s[%s]%s\n",
			colorBold, i+1, colorReset,
			colorCyan, m.Provider, colorReset,
			colorBold, m.Masked, colorReset,
			m.Entropy,
			statusColor, m.Status, colorReset,
		)
		fmt.Fprintf(w, "      Location: %s:%d\n", m.File, m.LineNumber)
		fmt.Fprintf(w, "      Rule:     %s (%s)\n\n", m.RuleID, m.Description)
	}
}

// RenderJSON writes findings as a formatted JSON payload.
func RenderJSON(w io.Writer, matches []detector.Match) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(matches)
}

// SaveJSONToFile dumps matches into a file path.
func SaveJSONToFile(filePath string, matches []detector.Match) error {
	f, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer f.Close()
	return RenderJSON(f, matches)
}
