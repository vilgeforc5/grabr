package grabr

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"

	enry "github.com/go-enry/go-enry/v2"
)

const maxHeuristicBytes = 2 * 1024 * 1024

var (
	envTokenAssignRe    = regexp.MustCompile(`^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*['"]?([^"'#\s]+)['"]?`)
	quotedAssignRe      = regexp.MustCompile("\\b([A-Za-z_][A-Za-z0-9_]*)\\b\\s*[:=]\\s*[\"'`]([^\"'`]+)[\"'`]")
	tokenKeywordRe      = regexp.MustCompile(`(?i)(token|secret|api[_-]?key|auth|bearer|access[_-]?key)`)
	hexOnlyRe           = regexp.MustCompile(`^[a-fA-F0-9]+$`)
	placeholderRe       = regexp.MustCompile(`(?i)(your[_-]?token|example|sample|changeme|replace_me|dummy|test|localhost|null|none|token_here)`)
	tokenNameVarRe      = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)
	tokenValueCharsetRe = regexp.MustCompile(`^[A-Za-z0-9._~+\-/:=]+$`)
)

type tokenNamesDocument struct {
	TokenNames []string `json:"token_names"`
}

type checkStrategy interface {
	Name() string
	Check(commit string, relPath string, line string, lineNo int, cfg config) []finding
}

type tokenHeuristic struct{}

func parseTokenNames(raw string) (map[string]struct{}, int, error) {
	items := strings.FieldsFunc(raw, func(r rune) bool {
		switch r {
		case ',', ';', '\n', '\r', '\t', ' ':
			return true
		default:
			return false
		}
	})
	seen := make(map[string]struct{}, len(items))
	for _, item := range items {
		name := strings.ToUpper(strings.TrimSpace(item))
		if name == "" {
			continue
		}
		if !tokenNameVarRe.MatchString(name) {
			return nil, 0, fmt.Errorf("invalid token variable name %q", item)
		}
		seen[name] = struct{}{}
	}
	if len(seen) == 0 {
		return nil, 0, errors.New("at least one token name is required for heuristics")
	}
	return seen, len(seen), nil
}

func normalizeTokenNames(names []string) ([]string, error) {
	seen := make(map[string]struct{}, len(names))
	normalized := make([]string, 0, len(names))
	for _, n := range names {
		name := strings.ToUpper(strings.TrimSpace(n))
		if name == "" {
			continue
		}
		if !tokenNameVarRe.MatchString(name) {
			return nil, fmt.Errorf("invalid token variable name %q in %s", n, DefaultTokenNamesFile)
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		normalized = append(normalized, name)
	}
	if len(normalized) == 0 {
		return nil, fmt.Errorf("no valid token names found in %s", DefaultTokenNamesFile)
	}
	sort.Strings(normalized)
	return normalized, nil
}

func resolveTokenNamesPath() (string, error) {
	candidates := make([]string, 0, 6)
	if envPath := strings.TrimSpace(os.Getenv("GRABR_TOKEN_NAMES_FILE")); envPath != "" {
		candidates = append(candidates, envPath)
	}

	if _, currentFile, _, ok := runtime.Caller(0); ok {
		candidates = append(candidates, filepath.Join(filepath.Dir(currentFile), DefaultTokenNamesFile))
	}

	if wd, err := os.Getwd(); err == nil {
		candidates = append(candidates, filepath.Join(wd, "pkg", DefaultTokenNamesFile))
		candidates = append(candidates, filepath.Join(wd, DefaultTokenNamesFile))
	}

	if exe, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exe)
		candidates = append(candidates, filepath.Join(exeDir, "pkg", DefaultTokenNamesFile))
		candidates = append(candidates, filepath.Join(exeDir, DefaultTokenNamesFile))
	}

	seen := map[string]struct{}{}
	tried := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		abs, err := filepath.Abs(candidate)
		if err == nil {
			candidate = abs
		}
		if _, ok := seen[candidate]; ok {
			continue
		}
		seen[candidate] = struct{}{}
		tried = append(tried, candidate)
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate, nil
		}
	}

	return "", fmt.Errorf(
		"could not find %s (set GRABR_TOKEN_NAMES_FILE). tried: %s",
		DefaultTokenNamesFile,
		strings.Join(tried, ", "),
	)
}

func runHeuristicTokenScan(repoDir string, cfg config, log logger) (scannerOutput, error) {
	var out scannerOutput
	strategies := []checkStrategy{
		tokenHeuristic{},
	}

	commits, err := listHeuristicCommits(repoDir, cfg, log)
	if err != nil {
		return out, fmt.Errorf("heuristic commit listing failed: %w", err)
	}
	log.debugf("heuristic commits queued: %d", len(commits))

	scannedFiles := 0
	for _, commit := range commits {
		paths, err := listCommitChangedFiles(repoDir, commit, cfg, log)
		if err != nil {
			out.warnings = append(out.warnings, fmt.Sprintf("heuristic commit file listing failed for %s: %v", commit, err))
			continue
		}
		for _, relPath := range paths {
			raw, scanned, warning := readCommitFileContent(repoDir, commit, relPath, cfg, log)
			if warning != "" {
				out.warnings = append(out.warnings, warning)
			}
			if !scanned {
				continue
			}
			scannedFiles++

			lines := strings.Split(string(raw), "\n")
			for idx, line := range lines {
				lineNo := idx + 1
				for _, strategy := range strategies {
					candidateFindings := strategy.Check(commit, relPath, line, lineNo, cfg)
					for i := range candidateFindings {
						if candidateFindings[i].CodeContext == nil {
							ctxLine := lineNo
							if candidateFindings[i].Line != nil && *candidateFindings[i].Line > 0 {
								ctxLine = *candidateFindings[i].Line
							}
							candidateFindings[i].CodeContext = buildCodeContext(lines, ctxLine)
						}
						if candidateFindings[i].Metadata == nil {
							candidateFindings[i].Metadata = map[string]any{}
						}
						candidateFindings[i].Metadata["scan_scope"] = "commit_history"
					}
					out.findings = append(out.findings, candidateFindings...)
				}
			}
		}
	}

	log.debugf("heuristic commits scanned: %d", len(commits))
	log.debugf("heuristic commit files scanned: %d", scannedFiles)
	log.infof("heuristic findings: %d", len(out.findings))
	return out, nil
}

func listHeuristicCommits(repoDir string, cfg config, log logger) ([]string, error) {
	res, err := runCmd(context.Background(), cfg.timeout, repoDir, log, "git", "rev-list", "--all", "--reverse")
	if err != nil {
		return nil, err
	}
	if res.code != 0 {
		return nil, fmt.Errorf("failed to list commits: %s", strings.TrimSpace(res.stderr))
	}

	seen := make(map[string]struct{})
	commits := make([]string, 0, 1024)
	sc := bufio.NewScanner(strings.NewReader(res.stdout))
	sc.Buffer(make([]byte, 0, 1024), 1024*1024)
	for sc.Scan() {
		commit := strings.TrimSpace(sc.Text())
		if commit == "" {
			continue
		}
		if _, ok := seen[commit]; ok {
			continue
		}
		seen[commit] = struct{}{}
		commits = append(commits, commit)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("failed parsing commit list: %w", err)
	}
	return commits, nil
}

func listCommitChangedFiles(repoDir string, commit string, cfg config, log logger) ([]string, error) {
	res, err := runCmd(
		context.Background(),
		cfg.timeout,
		repoDir,
		log,
		"git",
		"diff-tree",
		"--root",
		"--no-commit-id",
		"--name-only",
		"-z",
		"-r",
		commit,
	)
	if err != nil {
		return nil, err
	}
	if res.code != 0 {
		return nil, fmt.Errorf("git diff-tree failed: %s", strings.TrimSpace(res.stderr))
	}

	seen := make(map[string]struct{})
	paths := make([]string, 0, 128)
	rawParts := strings.Split(res.stdout, "\x00")
	for _, rawPath := range rawParts {
		path := normalizeGitObjectPath(rawPath)
		if path == "" {
			continue
		}
		if !cfg.includeNodeModules && pathInNodeModules(path) {
			continue
		}
		if !isCodeLikeFile(path) {
			continue
		}
		if _, ok := seen[path]; ok {
			continue
		}
		seen[path] = struct{}{}
		paths = append(paths, path)
	}
	sort.Strings(paths)
	return paths, nil
}

func readCommitFileContent(repoDir string, commit string, relPath string, cfg config, log logger) ([]byte, bool, string) {
	spec := commit + ":" + relPath
	sizeRes, err := runCmd(context.Background(), cfg.timeout, repoDir, log, "git", "cat-file", "-s", spec)
	if err != nil {
		return nil, false, fmt.Sprintf("heuristic content size check failed for %s %s: %v", commit, relPath, err)
	}
	if sizeRes.code != 0 {
		if isMissingPathAtCommit(sizeRes.stderr) {
			return nil, false, ""
		}
		return nil, false, fmt.Sprintf("heuristic content size check failed for %s %s: %s", commit, relPath, strings.TrimSpace(sizeRes.stderr))
	}

	size, err := strconv.ParseInt(strings.TrimSpace(sizeRes.stdout), 10, 64)
	if err != nil {
		return nil, false, fmt.Sprintf("heuristic content size parse failed for %s %s: %v", commit, relPath, err)
	}
	if size == 0 || size > maxHeuristicBytes {
		return nil, false, ""
	}

	contentRes, err := runCmd(context.Background(), cfg.timeout, repoDir, log, "git", "cat-file", "-p", spec)
	if err != nil {
		return nil, false, fmt.Sprintf("heuristic content read failed for %s %s: %v", commit, relPath, err)
	}
	if contentRes.code != 0 {
		if isMissingPathAtCommit(contentRes.stderr) {
			return nil, false, ""
		}
		return nil, false, fmt.Sprintf("heuristic content read failed for %s %s: %s", commit, relPath, strings.TrimSpace(contentRes.stderr))
	}

	raw := []byte(contentRes.stdout)
	if len(raw) == 0 || len(raw) > maxHeuristicBytes {
		return nil, false, ""
	}
	if isLikelyBinary(raw) {
		return nil, false, ""
	}
	return raw, true, ""
}

func isMissingPathAtCommit(stderr string) bool {
	msg := strings.ToLower(strings.TrimSpace(stderr))
	return strings.Contains(msg, "does not exist in") ||
		(strings.Contains(msg, "path ") && strings.Contains(msg, " not in "))
}

func normalizeGitObjectPath(raw string) string {
	path := strings.TrimSpace(raw)
	if path == "" {
		return ""
	}
	if strings.HasPrefix(path, "\"") && strings.HasSuffix(path, "\"") {
		if unquoted, err := strconv.Unquote(path); err == nil {
			path = unquoted
		}
	}
	return filepath.ToSlash(path)
}

func pathInNodeModules(path string) bool {
	path = filepath.ToSlash(path)
	return path == "node_modules" ||
		strings.HasPrefix(path, "node_modules/") ||
		strings.Contains(path, "/node_modules/")
}

func (h tokenHeuristic) Name() string {
	return "tokenHeuristic"
}

func (h tokenHeuristic) Check(commit string, relPath string, line string, lineNo int, cfg config) []finding {
	var out []finding
	seen := map[string]struct{}{}

	add := func(f finding) {
		key := f.Detector + "|" + f.File + "|" + ptrIntString(f.Line) + "|" + f.Preview
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		out = append(out, f)
	}

	if f, ok := h.checkNamedAssignment(commit, relPath, line, lineNo, cfg); ok {
		add(f)
	}

	if !isCodeLikeFile(relPath) {
		return out
	}

	matches := quotedAssignRe.FindAllStringSubmatch(line, -1)
	for _, m := range matches {
		if len(m) < 3 {
			continue
		}
		varName := strings.ToUpper(strings.TrimSpace(m[1]))
		value := cleanTokenCandidate(m[2])
		if !looksLikeTokenCandidate(value, cfg.minTokenLength) {
			continue
		}

		_, isNamed := cfg.tokenNameSet[varName]
		if !isNamed && !tokenKeywordRe.MatchString(varName) {
			continue
		}

		sev := SeveritySuspicious
		title := fmt.Sprintf("Possible hardcoded token in source (%s)", varName)
		if isNamed {
			sev = SeverityCritical
			title = fmt.Sprintf("Hardcoded token assigned to %s", varName)
		}

		add(newHeuristicFinding(
			commit,
			"HeuristicSourceToken",
			sev,
			title,
			relPath,
			lineNo,
			value,
			map[string]any{
				"strategy": h.Name(),
				"var_name": varName,
				"signal":   "source_assignment",
			},
		))
	}

	return out
}

func (h tokenHeuristic) checkNamedAssignment(commit string, relPath string, line string, lineNo int, cfg config) (finding, bool) {
	m := envTokenAssignRe.FindStringSubmatch(line)
	if len(m) < 3 {
		return finding{}, false
	}
	varName := strings.ToUpper(strings.TrimSpace(m[1]))
	value := cleanTokenCandidate(m[2])
	if _, ok := cfg.tokenNameSet[varName]; !ok {
		return finding{}, false
	}
	if !looksLikeTokenCandidate(value, cfg.minTokenLength) {
		return finding{}, false
	}
	return newHeuristicFinding(
		commit,
		"HeuristicNamedTokenAssignment",
		SeverityCritical,
		fmt.Sprintf("Potential exposed token for %s", varName),
		relPath,
		lineNo,
		value,
		map[string]any{
			"strategy": h.Name(),
			"var_name": varName,
			"signal":   "named_assignment",
		},
	), true
}

func newHeuristicFinding(
	commit string,
	detector string,
	severity string,
	title string,
	relPath string,
	lineNo int,
	value string,
	metadata map[string]any,
) finding {
	ln := lineNo
	preview := maskSecret(value)
	fingerprint := shortHash("heuristic", commit, detector, relPath, strconv.Itoa(lineNo), preview)
	return finding{
		ID:          shortHash("heuristic", commit, detector, relPath, strconv.Itoa(lineNo), value),
		Tool:        "heuristic",
		Severity:    severity,
		Title:       title,
		Detector:    detector,
		File:        relPath,
		Line:        &ln,
		Commit:      commit,
		Preview:     preview,
		CodeContext: nil,
		Fingerprint: "heuristic:" + fingerprint,
		Metadata:    metadata,
	}
}

func isCodeLikeFile(relPath string) bool {
	name := strings.ToLower(filepath.Base(relPath))
	if strings.HasPrefix(name, ".env") {
		return true
	}
	ext := strings.ToLower(filepath.Ext(relPath))
	lang, _ := enry.GetLanguageByExtension(ext)
	return lang != ""
}

func cleanTokenCandidate(raw string) string {
	clean := strings.TrimSpace(raw)
	clean = strings.Trim(clean, "\"'`")
	clean = strings.Trim(clean, ",;")
	return clean
}

func looksLikeTokenCandidate(value string, minLen int) bool {
	v := cleanTokenCandidate(value)
	if len(v) < minLen {
		return false
	}
	lower := strings.ToLower(v)
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		return false
	}
	if strings.ContainsAny(v, " \t\r\n") {
		return false
	}
	if placeholderRe.MatchString(v) || hasLongRepeatedRun(v, 8) {
		return false
	}
	if !tokenValueCharsetRe.MatchString(v) {
		return false
	}
	if hexOnlyRe.MatchString(v) && len(v) < 32 {
		return false
	}
	if !hasTokenDiversity(v) {
		return false
	}
	return true
}

func hasTokenDiversity(value string) bool {
	uniq := map[rune]struct{}{}
	hasLetter := false
	hasDigit := false
	hasSpecial := false
	for _, r := range value {
		uniq[r] = struct{}{}
		switch {
		case r >= 'a' && r <= 'z':
			hasLetter = true
		case r >= 'A' && r <= 'Z':
			hasLetter = true
		case r >= '0' && r <= '9':
			hasDigit = true
		default:
			hasSpecial = true
		}
	}
	if len(uniq) < 8 {
		return false
	}
	return (hasLetter && hasDigit) || (hasLetter && hasSpecial) || (hasDigit && hasSpecial)
}

func hasLongRepeatedRun(value string, threshold int) bool {
	if threshold <= 1 || value == "" {
		return false
	}
	runes := []rune(value)
	run := 1
	for i := 1; i < len(runes); i++ {
		if runes[i] == runes[i-1] {
			run++
			if run >= threshold {
				return true
			}
			continue
		}
		run = 1
	}
	return false
}

func isLikelyBinary(content []byte) bool {
	if len(content) == 0 {
		return false
	}
	sample := content
	if len(sample) > 512 {
		sample = sample[:512]
	}
	nonText := 0
	for _, b := range sample {
		if b == 0 {
			return true
		}
		if b < 9 || (b > 13 && b < 32) {
			nonText++
		}
	}
	return float64(nonText)/float64(len(sample)) > 0.20
}
