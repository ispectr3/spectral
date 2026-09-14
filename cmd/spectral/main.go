package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/ispectr3/spectral/pkg/detector"
	"github.com/ispectr3/spectral/pkg/output"
	"github.com/ispectr3/spectral/pkg/scanner"
	"github.com/ispectr3/spectral/pkg/verifier"
)

func main() {
	pathFlag := flag.String("path", ".", "Target file or directory to scan (use '-' for stdin)")
	threadsFlag := flag.Int("threads", 16, "Number of concurrent scanning workers")
	verifyFlag := flag.Bool("verify", false, "Verify detected secrets against provider APIs")
	verifiedOnlyFlag := flag.Bool("verified-only", false, "Filter output to active verified secrets only")
	gitFlag := flag.Bool("git", false, "Scan full Git commit history (requires git CLI)")
	jsonFlag := flag.Bool("json", false, "Output results in JSON format")
	outputFileFlag := flag.String("output", "", "Save results JSON to specified file path")
	sarifFileFlag := flag.String("sarif", "", "Export findings to SARIF 2.1.0 file")
	noBannerFlag := flag.Bool("no-banner", false, "Suppress ASCII banner")
	failOnLeakFlag := flag.Bool("fail-on-leak", false, "Exit with status code 1 if any secrets are detected")
	flag.Parse()

	if !*jsonFlag && !*noBannerFlag {
		output.PrintBanner(os.Stdout)
	}

	engine := detector.NewEngine()
	cfg := scanner.Config{
		Threads:        *threadsFlag,
		MaxFileSizeMB:  10,
		VerifyActive:   *verifyFlag || *verifiedOnlyFlag,
		OnlyVerified:   *verifiedOnlyFlag,
		ScanGitHistory: *gitFlag,
	}

	sc := scanner.NewScanner(engine, cfg)

	var matches []detector.Match
	var err error

	start := time.Now()

	// Check if reading from Stdin
	if *pathFlag == "-" {
		matches, err = sc.ScanReader(os.Stdin, "stdin")
	} else if *gitFlag {
		if !*jsonFlag {
			fmt.Printf("[*] Scanning Git commit history in: %s\n", *pathFlag)
		}
		matches, err = sc.ScanGitHistory(*pathFlag)
	} else {
		if !*jsonFlag {
			fmt.Printf("[*] Scanning target path: %s\n", *pathFlag)
		}
		matches, err = sc.ScanPath(*pathFlag)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Scan error: %v\n", err)
		os.Exit(1)
	}

	// Live verification if requested
	if cfg.VerifyActive && len(matches) > 0 {
		if !*jsonFlag {
			fmt.Printf("[*] Verifying %d secrets against provider APIs...\n", len(matches))
		}
		v := verifier.NewVerifier(4 * time.Second)
		ctx := context.Background()

		for i := range matches {
			status := v.Verify(ctx, &matches[i])
			matches[i].Status = status
		}
	}

	// Filter only verified if specified
	if *verifiedOnlyFlag {
		var filtered []detector.Match
		for _, m := range matches {
			if m.Status == "ACTIVE" {
				filtered = append(filtered, m)
			}
		}
		matches = filtered
	}

	elapsed := time.Since(start)

	if *jsonFlag {
		_ = output.RenderJSON(os.Stdout, matches)
	} else {
		output.RenderTable(os.Stdout, matches)
		fmt.Printf("[*] Scan completed in %v. Total findings: %d\n", elapsed, len(matches))
	}

	if *outputFileFlag != "" {
		if err := output.SaveJSONToFile(*outputFileFlag, matches); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed saving JSON output: %v\n", err)
		} else if !*jsonFlag {
			fmt.Printf("[+] Saved JSON report to: %s\n", *outputFileFlag)
		}
	}

	if *sarifFileFlag != "" {
		if err := output.SaveSARIFToFile(*sarifFileFlag, matches); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed saving SARIF output: %v\n", err)
		} else if !*jsonFlag {
			fmt.Printf("[+] Saved SARIF 2.1.0 report to: %s\n", *sarifFileFlag)
		}
	}

	if *failOnLeakFlag && len(matches) > 0 {
		os.Exit(1)
	}
}
