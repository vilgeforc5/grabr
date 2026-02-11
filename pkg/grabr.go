package grabr

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	SeverityCritical   = "CRITICAL"
	SeveritySuspicious = "SUSPICIOUS"
	DefaultTokenNamesFile = "token_names.json"
	DefaultMinTokenLen = 24
	DefaultTimeout     = 1800 * time.Second
	maxHeuristicBytes  = 2 * 1024 * 1024
)

type LogLevel int

const (
	LogLevelInfo LogLevel = iota
	LogLevelDebug
)

var (
	gitleaksCriticalRe   = regexp.MustCompile(`(?i)(private key|rsa private|ssh private|pgp private|service account key|pem file|pkcs)`)
	trufflehogCriticalRe = regexp.MustCompile(`(?i)(private.?key|ssh|rsa|pgp|service.?account|credential)`)
	envTokenAssignRe     = regexp.MustCompile(`^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*['"]?([^"'#\s]+)['"]?`)
	quotedAssignRe       = regexp.MustCompile("\\b([A-Za-z_][A-Za-z0-9_]*)\\b\\s*[:=]\\s*[\"'`]([^\"'`]+)[\"'`]")
	tokenKeywordRe       = regexp.MustCompile(`(?i)(token|secret|api[_-]?key|auth|bearer|access[_-]?key)`)
	hexOnlyRe            = regexp.MustCompile(`^[a-fA-F0-9]+$`)
	placeholderRe        = regexp.MustCompile(`(?i)(your[_-]?token|example|sample|changeme|replace_me|dummy|test|localhost|null|none|token_here)`)
	tokenNameVarRe       = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)
	tokenValueCharsetRe  = regexp.MustCompile(`^[A-Za-z0-9._~+\-/:=]+$`)
)

var codeExtensions = map[string]struct{}{
	".py":    {},
	".js":    {},
	".jsx":   {},
	".ts":    {},
	".tsx":   {},
	".go":    {},
	".java":  {},
	".rb":    {},
	".php":   {},
	".cs":    {},
	".c":     {},
	".cpp":   {},
	".h":     {},
	".hpp":   {},
	".rs":    {},
	".kt":    {},
	".swift": {},
	".scala": {},
	".sh":    {},
	".env":   {},
}

type config struct {
	repoURL            string
	timeout            time.Duration
	keepClone          bool
	cloneDir           string
	skipGitleaks       bool
	skipTruffle        bool
	skipHeuristics     bool
	includeNodeModules bool
	tokenNamesRaw      string
	tokenNameCount     int
	tokenNameSet       map[string]struct{}
	minTokenLength     int
	log                logger
}

type finding struct {
	ID          string         `json:"id"`
	Tool        string         `json:"tool"`
	Severity    string         `json:"severity"`
	Title       string         `json:"title"`
	Detector    string         `json:"detector,omitempty"`
	Verified    *bool          `json:"verified,omitempty"`
	File        string         `json:"file,omitempty"`
	Line        *int           `json:"line,omitempty"`
	Commit      string         `json:"commit,omitempty"`
	Preview     string         `json:"preview,omitempty"`
	Fingerprint string         `json:"fingerprint,omitempty"`
	Metadata    map[string]any `json:"metadata,omitempty"`
}

type report struct {
	RepoURL       string    `json:"repo_url"`
	ScannedAtUTC  string    `json:"scanned_at_utc"`
	FinishedAtUTC string    `json:"finished_at_utc"`
	DurationSec   float64   `json:"duration_seconds"`
	Summary       summary   `json:"summary"`
	Warnings      []string  `json:"warnings"`
	Findings      []finding `json:"findings"`
	RetainedClone string    `json:"retained_clone,omitempty"`
}

type summary struct {
	Total      int `json:"total_findings"`
	Critical   int `json:"critical"`
	Suspicious int `json:"suspicious"`
}

type cmdResult struct {
	stdout string
	stderr string
	code   int
}

type scannerOutput struct {
	findings []finding
	warnings []string
}

type tokenNamesDocument struct {
	TokenNames []string `json:"token_names"`
}

type Options struct {
	RepoURL            string
	Timeout            time.Duration
	KeepClone          bool
	CloneDir           string
	SkipGitleaks       bool
	SkipTrufflehog     bool
	SkipHeuristics     bool
	LogLevel           LogLevel
	LogOutput          io.Writer
	IncludeNodeModules bool
	TokenNames         string
	MinTokenLength     int
}

type Finding = finding
type Report = report
type Summary = summary

type checkStrategy interface {
	Name() string
	Check(relPath string, line string, lineNo int, cfg config) []finding
}

type tokenHeuristic struct{}

type logger struct {
	level LogLevel
	out   io.Writer
}

func (l logger) infof(format string, args ...any) {
	if l.level >= LogLevelInfo {
		fmt.Fprintf(l.out, "[INFO] "+format+"\n", args...)
	}
}

func (l logger) debugf(format string, args ...any) {
	if l.level >= LogLevelDebug {
		fmt.Fprintf(l.out, "[DEBUG] "+format+"\n", args...)
	}
}

func DefaultOptions(repoURL string) Options {
	return Options{
		RepoURL:            repoURL,
		Timeout:            DefaultTimeout,
		LogLevel:           LogLevelInfo,
		LogOutput:          os.Stderr,
		TokenNames:         "",
		MinTokenLength:     DefaultMinTokenLen,
		IncludeNodeModules: false,
	}
}

func ParseLogLevel(raw string) (LogLevel, error) {
	switch strings.ToUpper(strings.TrimSpace(raw)) {
	case "INFO":
		return LogLevelInfo, nil
	case "DEBUG":
		return LogLevelDebug, nil
	default:
		return LogLevelInfo, fmt.Errorf("invalid log level %q (allowed: INFO, DEBUG)", raw)
	}
}

func LoadDefaultTokenNames() ([]string, error) {
	path, err := resolveTokenNamesPath()
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read default token names file %q: %w", path, err)
	}

	// Support both {"token_names":[...]} and plain ["..."].
	var doc tokenNamesDocument
	if err := json.Unmarshal(raw, &doc); err == nil && len(doc.TokenNames) > 0 {
		return normalizeTokenNames(doc.TokenNames)
	}

	var names []string
	if err := json.Unmarshal(raw, &names); err != nil {
		return nil, fmt.Errorf("invalid JSON in %q: %w", path, err)
	}
	return normalizeTokenNames(names)
}

func LoadDefaultTokenNamesString() (string, error) {
	names, err := LoadDefaultTokenNames()
	if err != nil {
		return "", err
	}
	return strings.Join(names, ","), nil
}

func Run(ctx context.Context, opts Options) (Report, error) {
	cfg, err := normalizeOptions(opts)
	if err != nil {
		return Report{}, err
	}

	cfg.log.infof("Starting scan for %s", cfg.repoURL)
	if err := ensureTools(cfg); err != nil {
		return Report{}, err
	}

	started := time.Now().UTC()
	var warnings []string
	var allFindings []finding
	var repoDir string
	var retainedClone string

	cleanup := func() {}
	defer cleanup()

	repoDir, cleanup, err = prepareCloneDir(cfg.cloneDir, cfg.keepClone)
	if err != nil {
		return Report{}, err
	}
	cfg.log.debugf("Using clone directory: %s", repoDir)

	cfg.log.infof("Cloning repository...")
	if err := cloneRepo(ctx, cfg.repoURL, repoDir, cfg.timeout, cfg.log); err != nil {
		return Report{}, err
	}

	if !cfg.skipGitleaks {
		cfg.log.infof("Running gitleaks...")
		out, err := runGitleaks(ctx, repoDir, cfg.timeout, cfg.log)
		if err != nil {
			return Report{}, err
		}
		allFindings = append(allFindings, out.findings...)
		warnings = append(warnings, out.warnings...)
	}

	if !cfg.skipTruffle {
		cfg.log.infof("Running trufflehog...")
		out, err := runTrufflehog(ctx, repoDir, cfg.timeout, cfg.log)
		if err != nil {
			return Report{}, err
		}
		allFindings = append(allFindings, out.findings...)
		warnings = append(warnings, out.warnings...)
	}

	if !cfg.skipHeuristics {
		cfg.log.infof("Running heuristic token scan...")
		cfg.log.debugf("heuristic token names loaded: %d", cfg.tokenNameCount)
		out, err := runHeuristicTokenScan(repoDir, cfg, cfg.log)
		if err != nil {
			return Report{}, err
		}
		allFindings = append(allFindings, out.findings...)
		warnings = append(warnings, out.warnings...)
	}

	if cfg.keepClone {
		retainedClone = repoDir
	}

	filtered, dropped := filterFindings(allFindings, cfg)
	if dropped > 0 {
		msg := fmt.Sprintf("filtered %d finding(s) from node_modules paths (use --include-node-modules to keep them)", dropped)
		warnings = append(warnings, msg)
		cfg.log.infof(msg)
	}

	deduped := dedupe(filtered)
	finished := time.Now().UTC()
	rep := report{
		RepoURL:       cfg.repoURL,
		ScannedAtUTC:  started.Format(time.RFC3339),
		FinishedAtUTC: finished.Format(time.RFC3339),
		DurationSec:   finished.Sub(started).Seconds(),
		Summary: summary{
			Total:      len(deduped),
			Critical:   countBySeverity(deduped, SeverityCritical),
			Suspicious: countBySeverity(deduped, SeveritySuspicious),
		},
		Warnings:      warnings,
		Findings:      deduped,
		RetainedClone: retainedClone,
	}
	return rep, nil
}

func normalizeOptions(opts Options) (config, error) {
	cfg := config{
		repoURL:            strings.TrimSpace(opts.RepoURL),
		timeout:            opts.Timeout,
		keepClone:          opts.KeepClone,
		cloneDir:           strings.TrimSpace(opts.CloneDir),
		skipGitleaks:       opts.SkipGitleaks,
		skipTruffle:        opts.SkipTrufflehog,
		skipHeuristics:     opts.SkipHeuristics,
		includeNodeModules: opts.IncludeNodeModules,
		tokenNamesRaw:      opts.TokenNames,
		minTokenLength:     opts.MinTokenLength,
	}

	if cfg.repoURL == "" {
		return cfg, errors.New("repo URL is required")
	}
	if cfg.timeout == 0 {
		cfg.timeout = DefaultTimeout
	}
	if cfg.timeout < 0 {
		return cfg, errors.New("timeout must be > 0")
	}
	if cfg.skipGitleaks && cfg.skipTruffle && cfg.skipHeuristics {
		return cfg, errors.New("nothing to do: all scanners are skipped")
	}
	if cfg.minTokenLength == 0 {
		cfg.minTokenLength = DefaultMinTokenLen
	}
	if cfg.minTokenLength < 8 {
		return cfg, errors.New("min token length must be >= 8")
	}
	if !cfg.skipHeuristics {
		if cfg.tokenNamesRaw == "" {
			defaultTokenNamesRaw, err := LoadDefaultTokenNamesString()
			if err != nil {
				return cfg, err
			}
			cfg.tokenNamesRaw = defaultTokenNamesRaw
		}
		tokenNameSet, tokenNameCount, err := parseTokenNames(cfg.tokenNamesRaw)
		if err != nil {
			return cfg, err
		}
		cfg.tokenNameSet = tokenNameSet
		cfg.tokenNameCount = tokenNameCount
	}

	out := opts.LogOutput
	if out == nil {
		out = os.Stderr
	}
	level := opts.LogLevel
	if level != LogLevelInfo && level != LogLevelDebug {
		level = LogLevelInfo
	}
	cfg.log = logger{level: level, out: out}
	return cfg, nil
}

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

func ensureTools(cfg config) error {
	tools := []string{"git"}
	if !cfg.skipGitleaks {
		tools = append(tools, "gitleaks")
	}
	if !cfg.skipTruffle {
		tools = append(tools, "trufflehog")
	}
	for _, tool := range tools {
		if _, err := exec.LookPath(tool); err != nil {
			return fmt.Errorf("required executable %q not found in PATH", tool)
		}
	}
	return nil
}

func prepareCloneDir(cloneDir string, keepClone bool) (string, func(), error) {
	if cloneDir != "" {
		abs, err := filepath.Abs(cloneDir)
		if err != nil {
			return "", func() {}, fmt.Errorf("invalid --clone-dir: %w", err)
		}
		info, err := os.Stat(abs)
		if err == nil && !info.IsDir() {
			return "", func() {}, fmt.Errorf("--clone-dir is not a directory: %s", abs)
		}
		if err == nil {
			entries, readErr := os.ReadDir(abs)
			if readErr != nil {
				return "", func() {}, fmt.Errorf("failed reading --clone-dir: %w", readErr)
			}
			if len(entries) > 0 {
				return "", func() {}, fmt.Errorf("--clone-dir must be empty: %s", abs)
			}
		}
		if errors.Is(err, os.ErrNotExist) {
			if mkErr := os.MkdirAll(abs, 0o755); mkErr != nil {
				return "", func() {}, fmt.Errorf("failed creating --clone-dir: %w", mkErr)
			}
		}
		return abs, func() {}, nil
	}

	dir, err := os.MkdirTemp("", "grabr-repo-*")
	if err != nil {
		return "", func() {}, fmt.Errorf("failed to create temp clone dir: %w", err)
	}
	cleanup := func() {
		if !keepClone {
			_ = os.RemoveAll(dir)
		}
	}
	return dir, cleanup, nil
}

func cloneRepo(ctx context.Context, repoURL string, repoDir string, timeout time.Duration, log logger) error {
	res, err := runCmd(ctx, timeout, "", log, "git", "clone", repoURL, repoDir)
	if err != nil {
		return err
	}
	if res.code != 0 {
		return fmt.Errorf("failed to clone repository: %s", strings.TrimSpace(res.stderr))
	}
	return nil
}

func runGitleaks(ctx context.Context, repoDir string, timeout time.Duration, log logger) (scannerOutput, error) {
	var out scannerOutput
	reportFile, err := os.CreateTemp("", "gitleaks-*.json")
	if err != nil {
		return out, fmt.Errorf("failed to create gitleaks report file: %w", err)
	}
	reportPath := reportFile.Name()
	_ = reportFile.Close()
	defer os.Remove(reportPath)

	res, err := runCmd(
		ctx,
		timeout,
		"",
		log,
		"gitleaks",
		"git",
		"--report-format",
		"json",
		"--report-path",
		reportPath,
		"--exit-code",
		"0",
		"--no-banner",
		repoDir,
	)
	if err != nil {
		return out, err
	}
	if res.code != 0 {
		out.warnings = append(out.warnings, fmt.Sprintf("gitleaks exited with code %d: %s", res.code, strings.TrimSpace(res.stderr)))
	}
	log.debugf("gitleaks exit code: %d", res.code)

	content, err := os.ReadFile(reportPath)
	if err != nil {
		out.warnings = append(out.warnings, fmt.Sprintf("failed reading gitleaks report: %v", err))
		return out, nil
	}
	if len(strings.TrimSpace(string(content))) == 0 {
		return out, nil
	}

	var entries []map[string]any
	if err := json.Unmarshal(content, &entries); err != nil {
		out.warnings = append(out.warnings, fmt.Sprintf("failed parsing gitleaks report: %v", err))
		return out, nil
	}

	for _, entry := range entries {
		detector := asString(entry["RuleID"])
		filePath := asString(entry["File"])
		line := asIntPtr(entry["StartLine"])
		commit := asString(entry["Commit"])
		secret := asString(entry["Secret"])
		match := asString(entry["Match"])
		preview := maskSecret(firstNonEmpty(secret, match))
		fingerprint := asString(entry["Fingerprint"])
		title := firstNonEmpty(asString(entry["Description"]), "Potential secret detected")
		sev := gitleaksSeverity(entry)

		meta := map[string]any{
			"author":  asString(entry["Author"]),
			"date":    asString(entry["Date"]),
			"message": asString(entry["Message"]),
			"tags":    entry["Tags"],
		}

		out.findings = append(out.findings, finding{
			ID:          shortHash("gitleaks", detector, filePath, ptrIntString(line), commit, fingerprint, preview),
			Tool:        "gitleaks",
			Severity:    sev,
			Title:       title,
			Detector:    detector,
			Verified:    nil,
			File:        filePath,
			Line:        line,
			Commit:      commit,
			Preview:     preview,
			Fingerprint: fingerprint,
			Metadata:    meta,
		})
	}
	log.infof("gitleaks findings: %d", len(out.findings))

	return out, nil
}

func runTrufflehog(ctx context.Context, repoDir string, timeout time.Duration, log logger) (scannerOutput, error) {
	var out scannerOutput
	absRepo, err := filepath.Abs(repoDir)
	if err != nil {
		return out, fmt.Errorf("failed to resolve repo path: %w", err)
	}

	res, err := runCmd(
		ctx,
		timeout,
		"",
		log,
		"trufflehog",
		"git",
		"--json",
		"--results=verified,unknown",
		"file://"+absRepo,
	)
	if err != nil {
		return out, err
	}
	if res.code != 0 && res.code != 1 {
		out.warnings = append(out.warnings, fmt.Sprintf("trufflehog exited with code %d: %s", res.code, strings.TrimSpace(res.stderr)))
	}
	log.debugf("trufflehog exit code: %d", res.code)

	sc := bufio.NewScanner(strings.NewReader(res.stdout))
	lineNum := 0
	for sc.Scan() {
		lineNum++
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}

		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			out.warnings = append(out.warnings, fmt.Sprintf("trufflehog non-JSON line %d skipped", lineNum))
			continue
		}

		detector := asString(entry["DetectorName"])
		verified := asBoolPtr(entry["Verified"])
		sev := trufflehogSeverity(entry)
		preview := maskSecret(firstNonEmpty(asString(entry["Redacted"]), asString(entry["Raw"])))

		gitMeta := parseTrufflehogGitMetadata(entry)
		filePath := asString(gitMeta["file"])
		linePtr := asIntPtr(gitMeta["line"])
		commit := asString(gitMeta["commit"])
		fingerprint := strings.TrimSpace(firstNonEmpty(asString(entry["DetectorType"]), asString(entry["DecoderName"])))

		meta := map[string]any{
			"detector_type": asString(entry["DetectorType"]),
			"decoder_name":  asString(entry["DecoderName"]),
			"source_type":   asString(entry["SourceType"]),
		}

		out.findings = append(out.findings, finding{
			ID:          shortHash("trufflehog", detector, filePath, ptrIntString(linePtr), commit, preview),
			Tool:        "trufflehog",
			Severity:    sev,
			Title:       firstNonEmpty(detector, "Potential secret") + " detected",
			Detector:    detector,
			Verified:    verified,
			File:        filePath,
			Line:        linePtr,
			Commit:      commit,
			Preview:     preview,
			Fingerprint: fingerprint,
			Metadata:    meta,
		})
	}
	if err := sc.Err(); err != nil {
		out.warnings = append(out.warnings, fmt.Sprintf("trufflehog output scan warning: %v", err))
	}
	log.infof("trufflehog findings: %d", len(out.findings))

	return out, nil
}

func runHeuristicTokenScan(repoDir string, cfg config, log logger) (scannerOutput, error) {
	var out scannerOutput
	strategies := []checkStrategy{
		tokenHeuristic{},
	}

	scannedFiles := 0
	err := filepath.WalkDir(repoDir, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			out.warnings = append(out.warnings, fmt.Sprintf("heuristic walk warning at %s: %v", path, walkErr))
			return nil
		}

		if d.IsDir() {
			name := d.Name()
			if name == ".git" {
				return filepath.SkipDir
			}
			if !cfg.includeNodeModules && name == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}

		info, err := d.Info()
		if err != nil {
			out.warnings = append(out.warnings, fmt.Sprintf("heuristic stat warning at %s: %v", path, err))
			return nil
		}
		if info.Size() == 0 || info.Size() > maxHeuristicBytes {
			return nil
		}

		raw, err := os.ReadFile(path)
		if err != nil {
			out.warnings = append(out.warnings, fmt.Sprintf("heuristic read warning at %s: %v", path, err))
			return nil
		}
		if isLikelyBinary(raw) {
			return nil
		}

		relPath, err := filepath.Rel(repoDir, path)
		if err != nil {
			relPath = path
		}
		relPath = filepath.ToSlash(relPath)

		scannedFiles++
		lines := strings.Split(string(raw), "\n")
		for idx, line := range lines {
			lineNo := idx + 1
			for _, strategy := range strategies {
				out.findings = append(out.findings, strategy.Check(relPath, line, lineNo, cfg)...)
			}
		}
		return nil
	})
	if err != nil {
		return out, fmt.Errorf("heuristic scan failed: %w", err)
	}

	log.debugf("heuristic files scanned: %d", scannedFiles)
	log.infof("heuristic findings: %d", len(out.findings))
	return out, nil
}

func (h tokenHeuristic) Name() string {
	return "tokenHeuristic"
}

func (h tokenHeuristic) Check(relPath string, line string, lineNo int, cfg config) []finding {
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

	if f, ok := h.checkNamedAssignment(relPath, line, lineNo, cfg); ok {
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

func (h tokenHeuristic) checkNamedAssignment(relPath string, line string, lineNo int, cfg config) (finding, bool) {
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
	fingerprint := shortHash("heuristic", detector, relPath, strconv.Itoa(lineNo), preview)
	return finding{
		ID:          shortHash("heuristic", detector, relPath, strconv.Itoa(lineNo), value),
		Tool:        "heuristic",
		Severity:    severity,
		Title:       title,
		Detector:    detector,
		File:        relPath,
		Line:        &ln,
		Preview:     preview,
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
	_, ok := codeExtensions[ext]
	return ok
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
	// Tokens that look real usually mix classes, not plain alphabetic words.
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

func parseTrufflehogGitMetadata(entry map[string]any) map[string]any {
	sourceMeta, ok := entry["SourceMetadata"].(map[string]any)
	if !ok {
		return map[string]any{}
	}
	data, ok := sourceMeta["Data"].(map[string]any)
	if !ok {
		return map[string]any{}
	}
	gitMeta, ok := data["Git"].(map[string]any)
	if !ok {
		return map[string]any{}
	}
	return gitMeta
}

func gitleaksSeverity(entry map[string]any) string {
	text := strings.Join([]string{
		asString(entry["RuleID"]),
		asString(entry["Description"]),
		asString(entry["File"]),
		asString(entry["Match"]),
		asString(entry["Secret"]),
	}, " ")
	if gitleaksCriticalRe.MatchString(text) {
		return SeverityCritical
	}
	return SeveritySuspicious
}

func trufflehogSeverity(entry map[string]any) string {
	if v, ok := entry["Verified"].(bool); ok && v {
		return SeverityCritical
	}
	if trufflehogCriticalRe.MatchString(asString(entry["DetectorName"])) {
		return SeverityCritical
	}
	return SeveritySuspicious
}

func dedupe(findings []finding) []finding {
	seen := make(map[string]struct{}, len(findings))
	out := make([]finding, 0, len(findings))
	for _, f := range findings {
		key := strings.Join([]string{
			f.Tool,
			f.Detector,
			f.File,
			ptrIntString(f.Line),
			f.Commit,
			f.Preview,
		}, "|")
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, f)
	}
	return out
}

func filterFindings(findings []finding, cfg config) ([]finding, int) {
	filtered := make([]finding, 0, len(findings))
	dropped := 0
	for _, f := range findings {
		if shouldDropFinding(f, cfg) {
			dropped++
			continue
		}
		filtered = append(filtered, f)
	}
	return filtered, dropped
}

func shouldDropFinding(f finding, cfg config) bool {
	if cfg.includeNodeModules || f.File == "" {
		return false
	}
	path := filepath.ToSlash(f.File)
	return path == "node_modules" ||
		strings.HasPrefix(path, "node_modules/") ||
		strings.Contains(path, "/node_modules/")
}

func countBySeverity(findings []finding, severity string) int {
	n := 0
	for _, f := range findings {
		if f.Severity == severity {
			n++
		}
	}
	return n
}

func DefaultReportPath() string {
	return fmt.Sprintf("scan-report-%s.json", time.Now().UTC().Format("20060102T150405Z"))
}

func WriteReport(path string, rep Report) error {
	blob, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, blob, 0o644)
}

func PrintSummary(w io.Writer, reportPath string, rep Report) {
	fmt.Fprintln(w, "Scan complete.")
	fmt.Fprintf(w, "Findings: %d\n", rep.Summary.Total)
	fmt.Fprintf(w, "  %s: %d\n", SeverityCritical, rep.Summary.Critical)
	fmt.Fprintf(w, "  %s: %d\n", SeveritySuspicious, rep.Summary.Suspicious)

	toolCounts := map[string]int{}
	for _, f := range rep.Findings {
		toolCounts[f.Tool]++
	}
	tools := make([]string, 0, len(toolCounts))
	for tool := range toolCounts {
		tools = append(tools, tool)
	}
	sort.Strings(tools)
	fmt.Fprintln(w, "By tool:")
	for _, tool := range tools {
		fmt.Fprintf(w, "  %s: %d\n", tool, toolCounts[tool])
	}
	if len(rep.Warnings) > 0 {
		fmt.Fprintf(w, "Warnings: %d (see report JSON)\n", len(rep.Warnings))
	}
	fmt.Fprintf(w, "Report: %s\n", reportPath)
}

func runCmd(parent context.Context, timeout time.Duration, cwd string, log logger, name string, args ...string) (cmdResult, error) {
	var result cmdResult

	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	log.debugf("exec: %s %s", name, strings.Join(args, " "))
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = cwd
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	result.stdout = stdout.String()
	result.stderr = stderr.String()

	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			result.code = exitErr.ExitCode()
			log.debugf("exec finished with exit code %d: %s", result.code, name)
			return result, nil
		}
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return result, fmt.Errorf("command timed out after %s: %s %s", timeout, name, strings.Join(args, " "))
		}
		return result, fmt.Errorf("failed running command %q: %w", name, err)
	}

	result.code = 0
	log.debugf("exec finished with exit code 0: %s", name)
	return result, nil
}

func shortHash(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(sum[:8])
}

func maskSecret(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if len(raw) <= 6 {
		return strings.Repeat("*", len(raw))
	}
	return raw[:3] + strings.Repeat("*", len(raw)-6) + raw[len(raw)-3:]
}

func asString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case fmt.Stringer:
		return t.String()
	case json.Number:
		return t.String()
	case float64:
		if t == float64(int64(t)) {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'f', -1, 64)
	case int:
		return strconv.Itoa(t)
	case int64:
		return strconv.FormatInt(t, 10)
	default:
		return ""
	}
}

func asIntPtr(v any) *int {
	switch t := v.(type) {
	case int:
		x := t
		return &x
	case int32:
		x := int(t)
		return &x
	case int64:
		x := int(t)
		return &x
	case float64:
		x := int(t)
		return &x
	case json.Number:
		if n, err := t.Int64(); err == nil {
			x := int(n)
			return &x
		}
	case string:
		if t == "" {
			return nil
		}
		if n, err := strconv.Atoi(t); err == nil {
			x := n
			return &x
		}
	}
	return nil
}

func asBoolPtr(v any) *bool {
	b, ok := v.(bool)
	if !ok {
		return nil
	}
	x := b
	return &x
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func ptrIntString(v *int) string {
	if v == nil {
		return ""
	}
	return strconv.Itoa(*v)
}
