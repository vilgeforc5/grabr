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
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	SeverityCritical      = "CRITICAL"
	SeveritySuspicious    = "SUSPICIOUS"
	DefaultTokenNamesFile = "token_names.json"
	DefaultMinTokenLen    = 24
	DefaultTimeout        = 1800 * time.Second
)

type LogLevel int

const (
	LogLevelInfo LogLevel = iota
	LogLevelDebug
)

var (
	gitleaksCriticalRe   = regexp.MustCompile(`(?i)(private key|rsa private|ssh private|pgp private|service account key|pem file|pkcs)`)
	trufflehogCriticalRe = regexp.MustCompile(`(?i)(private.?key|ssh|rsa|pgp|service.?account|credential)`)
)

type config struct {
	repoURL            string
	localRepoPath      string
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
	CodeContext *CodeContext   `json:"code_context,omitempty"`
	Fingerprint string         `json:"fingerprint,omitempty"`
	Metadata    map[string]any `json:"metadata,omitempty"`
}

type report struct {
	RepoURL       string    `json:"repo_url"`
	RepoPath      string    `json:"repo_path,omitempty"`
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

type Options struct {
	RepoURL            string
	LocalRepoPath      string
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

	target := cfg.repoURL
	if cfg.localRepoPath != "" {
		target = cfg.localRepoPath
	}
	cfg.log.infof("Starting scan for %s", target)
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

	if cfg.localRepoPath != "" {
		repoDir = cfg.localRepoPath
		cfg.log.infof("Using local repository path (clone skipped)")
		cfg.log.debugf("Using local repository: %s", repoDir)
	} else {
		repoDir, cleanup, err = prepareCloneDir(cfg.cloneDir, cfg.keepClone)
		if err != nil {
			return Report{}, err
		}
		cfg.log.debugf("Using clone directory: %s", repoDir)

		cfg.log.infof("Cloning repository...")
		if err := cloneRepo(ctx, cfg.repoURL, repoDir, cfg.timeout, cfg.log); err != nil {
			return Report{}, err
		}
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
		RepoPath:      cfg.localRepoPath,
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
		localRepoPath:      strings.TrimSpace(opts.LocalRepoPath),
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

	if cfg.repoURL == "" && cfg.localRepoPath == "" {
		return cfg, errors.New("either repo URL or local repository path is required")
	}
	if cfg.repoURL != "" && cfg.localRepoPath != "" {
		return cfg, errors.New("use either repo URL or local repository path, not both")
	}
	if cfg.localRepoPath != "" {
		if cfg.cloneDir != "" {
			return cfg, errors.New("--clone-dir can only be used with remote repo URLs")
		}
		if cfg.keepClone {
			return cfg, errors.New("--keep-clone can only be used with remote repo URLs")
		}
		absPath, err := filepath.Abs(cfg.localRepoPath)
		if err != nil {
			return cfg, fmt.Errorf("invalid local repository path: %w", err)
		}
		info, err := os.Stat(absPath)
		if err != nil {
			return cfg, fmt.Errorf("failed to access local repository path %q: %w", absPath, err)
		}
		if !info.IsDir() {
			return cfg, fmt.Errorf("local repository path is not a directory: %s", absPath)
		}
		gitDir := filepath.Join(absPath, ".git")
		if _, err := os.Stat(gitDir); err != nil {
			return cfg, fmt.Errorf("local repository path does not look like a git repository (missing .git): %s", absPath)
		}
		cfg.localRepoPath = absPath
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
	contextResolver := newCodeContextResolver(repoDir)
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
			CodeContext: contextResolver.resolve(filePath, line),
			Fingerprint: fingerprint,
			Metadata:    meta,
		})
	}
	log.infof("gitleaks findings: %d", len(out.findings))

	return out, nil
}

func runTrufflehog(ctx context.Context, repoDir string, timeout time.Duration, log logger) (scannerOutput, error) {
	var out scannerOutput
	contextResolver := newCodeContextResolver(repoDir)
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
			CodeContext: contextResolver.resolve(filePath, linePtr),
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
	return raw
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
