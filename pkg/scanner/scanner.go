package scanner

import (
	"bufio"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/ispectr3/spectral/pkg/detector"
)

var defaultIgnoredDirs = map[string]bool{
	".git":         true,
	"node_modules": true,
	"vendor":       true,
	".venv":        true,
	"venv":         true,
	"__pycache__":  true,
	"dist":         true,
	"build":        true,
	"target":       true,
	".cache":       true,
	".idea":        true,
	".vscode":      true,
}

// Config holds scanner options.
type Config struct {
	Threads        int
	MaxFileSizeMB  int64
	EntropyMin     float64
	VerifyActive   bool
	OnlyVerified   bool
	ScanGitHistory bool
}

// Scanner handles concurrent file traversal and inspection.
type Scanner struct {
	engine *detector.Engine
	cfg    Config
}

// NewScanner initializes a Scanner instance.
func NewScanner(engine *detector.Engine, cfg Config) *Scanner {
	if cfg.Threads <= 0 {
		cfg.Threads = 16
	}
	if cfg.MaxFileSizeMB <= 0 {
		cfg.MaxFileSizeMB = 10 // 10MB default
	}
	return &Scanner{
		engine: engine,
		cfg:    cfg,
	}
}

// ScanPath recursively scans a directory or single file for exposed secrets.
func (s *Scanner) ScanPath(root string) ([]detector.Match, error) {
	fi, err := os.Stat(root)
	if err != nil {
		return nil, err
	}

	if !fi.IsDir() {
		return s.ScanFile(root)
	}

	var files []string
	err = filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if info.IsDir() {
			base := info.Name()
			if defaultIgnoredDirs[base] {
				return filepath.SkipDir
			}
			return nil
		}
		if info.Size() > s.cfg.MaxFileSizeMB*1024*1024 {
			return nil
		}
		files = append(files, path)
		return nil
	})
	if err != nil {
		return nil, err
	}

	fileChan := make(chan string, len(files))
	for _, f := range files {
		fileChan <- f
	}
	close(fileChan)

	var mu sync.Mutex
	var allMatches []detector.Match
	var wg sync.WaitGroup

	for i := 0; i < s.cfg.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for file := range fileChan {
				matches, _ := s.ScanFile(file)
				if len(matches) > 0 {
					mu.Lock()
					allMatches = append(allMatches, matches...)
					mu.Unlock()
				}
			}
		}()
	}

	wg.Wait()
	return allMatches, nil
}

// ScanFile scans an individual file on disk.
func (s *Scanner) ScanFile(filePath string) ([]detector.Match, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// Check if binary file (inspect first 512 bytes for null byte)
	buf := make([]byte, 512)
	n, err := file.Read(buf)
	if err != nil && err != io.EOF {
		return nil, err
	}
	if bytes.IndexByte(buf[:n], 0) != -1 {
		// Binary file detected; skip
		return nil, nil
	}

	// Reset file offset
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}

	return s.ScanReader(file, filePath)
}

// ScanReader reads lines from any io.Reader.
func (s *Scanner) ScanReader(r io.Reader, label string) ([]detector.Match, error) {
	var matches []detector.Match
	scanner := bufio.NewScanner(r)

	// Allow line buffers up to 1MB
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	lineNum := 1
	for scanner.Scan() {
		line := scanner.Text()
		lineMatches := s.engine.ScanLine(line, lineNum, label)
		if len(lineMatches) > 0 {
			matches = append(matches, lineMatches...)
		}
		lineNum++
	}

	return matches, scanner.Err()
}

// ScanGitHistory scans commits in a git repository if git CLI is available.
func (s *Scanner) ScanGitHistory(repoPath string) ([]detector.Match, error) {
	return ScanGit(s.engine, repoPath)
}
