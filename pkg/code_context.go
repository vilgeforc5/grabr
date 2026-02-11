package grabr

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type CodeContext struct {
	StartLine     int    `json:"start_line"`
	HighlightLine int    `json:"highlight_line"`
	EndLine       int    `json:"end_line"`
	Snippet       string `json:"snippet"`
}

type codeContextResolver struct {
	repoDir string
	cache   map[string][]string
}

func newCodeContextResolver(repoDir string) *codeContextResolver {
	return &codeContextResolver{
		repoDir: repoDir,
		cache:   make(map[string][]string),
	}
}

func (r *codeContextResolver) resolve(filePath string, line *int) *CodeContext {
	if r == nil || line == nil || *line <= 0 {
		return nil
	}
	filePath = strings.TrimSpace(filePath)
	if filePath == "" {
		return nil
	}

	lines, ok := r.cache[filePath]
	if !ok {
		normalized := filepath.FromSlash(filePath)
		fullPath := normalized
		if !filepath.IsAbs(fullPath) {
			fullPath = filepath.Join(r.repoDir, normalized)
		}
		content, err := os.ReadFile(fullPath)
		if err != nil {
			return nil
		}
		lines = strings.Split(string(content), "\n")
		r.cache[filePath] = lines
	}

	idx := *line - 1
	return buildCodeContext(lines, idx+1)
}

func buildCodeContext(lines []string, highlightLine int) *CodeContext {
	if highlightLine <= 0 {
		return nil
	}
	idx := highlightLine - 1
	if idx < 0 || idx >= len(lines) {
		return nil
	}

	start := idx - 1
	if start < 0 {
		start = idx
	}
	end := idx + 1
	if end >= len(lines) {
		end = idx
	}

	var block []string
	for i := start; i <= end; i++ {
		prefix := "   "
		if i == idx {
			prefix = ">> "
		}
		block = append(block, fmt.Sprintf("%s%6d | %s", prefix, i+1, lines[i]))
	}

	return &CodeContext{
		StartLine:     start + 1,
		HighlightLine: idx + 1,
		EndLine:       end + 1,
		Snippet:       strings.Join(block, "\n"),
	}
}
