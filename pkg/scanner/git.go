package scanner

import (
	"bufio"
	"os/exec"
	"strconv"
	"strings"

	"github.com/ispectr3/spectral/pkg/detector"
)

// ScanGit inspects git commit diffs for secrets added across history.
func ScanGit(engine *detector.Engine, repoPath string) ([]detector.Match, error) {
	// git log -p -U0 will output patch diffs for all commits
	cmd := exec.Command("git", "-C", repoPath, "log", "-p", "-U0", "--no-color")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	var matches []detector.Match
	scanner := bufio.NewScanner(stdout)

	var currentFile string
	var currentCommit string
	lineNum := 0

	for scanner.Scan() {
		line := scanner.Text()

		if strings.HasPrefix(line, "commit ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				currentCommit = parts[1][:8]
			}
			continue
		}

		if strings.HasPrefix(line, "diff --git ") {
			parts := strings.Fields(line)
			if len(parts) >= 4 {
				currentFile = strings.TrimPrefix(parts[3], "b/")
			}
			continue
		}

		if strings.HasPrefix(line, "@@ ") {
			// Parse hunk header: @@ -1,1 +1,1 @@
			hunkParts := strings.Split(line, " ")
			if len(hunkParts) >= 3 {
				targetHunk := strings.TrimPrefix(hunkParts[2], "+")
				subParts := strings.Split(targetHunk, ",")
				if parsed, err := strconv.Atoi(subParts[0]); err == nil {
					lineNum = parsed
				}
			}
			continue
		}

		// Only inspect added lines in diffs (starts with '+', but not '+++')
		if strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++") {
			content := strings.TrimPrefix(line, "+")
			fileRef := currentFile
			if currentCommit != "" {
				fileRef = currentFile + " (commit: " + currentCommit + ")"
			}
			found := engine.ScanLine(content, lineNum, fileRef)
			if len(found) > 0 {
				matches = append(matches, found...)
			}
			lineNum++
		}
	}

	_ = cmd.Wait()
	return matches, nil
}
