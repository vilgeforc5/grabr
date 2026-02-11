package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"grabr/pkg"
)

type cliConfig struct {
	outputPath string
	options    grabr.Options
}

func main() {
	cfg, err := parseArgs(os.Args[1:])
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}

	report, err := grabr.Run(context.Background(), cfg.options)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	outputPath := cfg.outputPath
	if outputPath == "" {
		outputPath = grabr.DefaultReportPath()
	}
	if err := grabr.WriteReport(outputPath, report); err != nil {
		fmt.Fprintf(os.Stderr, "error: failed to write report: %v\n", err)
		os.Exit(1)
	}

	grabr.PrintSummary(os.Stdout, outputPath, report)
	if report.RetainedClone != "" {
		fmt.Printf("Cloned repository retained at: %s\n", report.RetainedClone)
	}
}

func parseArgs(args []string) (cliConfig, error) {
	var cfg cliConfig
	var timeoutSec int
	var logLevelRaw string

	if len(args) > 0 && strings.EqualFold(args[0], "help") {
		printHelp(os.Stdout)
		return cfg, flag.ErrHelp
	}

	fs := flag.NewFlagSet("grabr", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() {
		printHelp(fs.Output())
	}

	defaults := grabr.DefaultOptions("")
	fs.StringVar(&cfg.outputPath, "output", "", "Path to output JSON report")
	fs.StringVar(&cfg.outputPath, "o", "", "Path to output JSON report")
	fs.IntVar(&timeoutSec, "timeout", int(grabr.DefaultTimeout.Seconds()), "Timeout in seconds per scanner command")
	fs.StringVar(&cfg.options.LocalRepoPath, "local-repo", "", "Path to local git repository (alternative to <repo_url>)")
	fs.BoolVar(&cfg.options.KeepClone, "keep-clone", defaults.KeepClone, "Keep cloned repository directory")
	fs.StringVar(&cfg.options.CloneDir, "clone-dir", defaults.CloneDir, "Directory to clone repo into (must be empty)")
	fs.BoolVar(&cfg.options.SkipGitleaks, "skip-gitleaks", defaults.SkipGitleaks, "Skip gitleaks scan")
	fs.BoolVar(&cfg.options.SkipTrufflehog, "skip-trufflehog", defaults.SkipTrufflehog, "Skip trufflehog scan")
	fs.BoolVar(&cfg.options.SkipHeuristics, "skip-heuristics", defaults.SkipHeuristics, "Skip custom token heuristics scan (git history)")
	fs.BoolVar(&cfg.options.IncludeNodeModules, "include-node-modules", defaults.IncludeNodeModules, "Include findings in node_modules paths")
	fs.StringVar(&cfg.options.TokenNames, "token-names", "", "Token variable names string (comma/space/newline/semicolon separated). Empty means load from pkg/token_names.json")
	fs.IntVar(&cfg.options.MinTokenLength, "heuristic-min-token-length", grabr.DefaultMinTokenLen, "Minimum token length for heuristic detection")
	fs.StringVar(&logLevelRaw, "log-level", "INFO", "Log level: INFO or DEBUG")

	if err := fs.Parse(args); err != nil {
		return cfg, err
	}
	if timeoutSec <= 0 {
		return cfg, errors.New("--timeout must be > 0")
	}

	rest := fs.Args()
	localRepo := strings.TrimSpace(cfg.options.LocalRepoPath)
	switch {
	case localRepo != "" && len(rest) > 0:
		return cfg, errors.New("use either --local-repo <path> or <repo_url>, not both")
	case localRepo == "" && len(rest) != 1:
		return cfg, errors.New("usage: grabr [flags] <repo_url> OR grabr [flags] --local-repo <path> (run 'grabr help')")
	case localRepo != "":
		cfg.options.RepoURL = ""
	default:
		cfg.options.RepoURL = rest[0]
	}
	cfg.options.Timeout = time.Duration(timeoutSec) * time.Second
	cfg.options.LogOutput = os.Stderr

	level, err := grabr.ParseLogLevel(logLevelRaw)
	if err != nil {
		return cfg, err
	}
	cfg.options.LogLevel = level
	return cfg, nil
}

func printHelp(w io.Writer) {
	_, _ = fmt.Fprint(w, `grabr scans git repositories for potential leaked secrets using gitleaks, trufflehog, and heuristic checks.

Usage:
  grabr [flags] <repo_url>
  grabr [flags] --local-repo <path>
  grabr help

Examples:
  go run . https://github.com/OWNER/REPO.git
  go run . --local-repo /path/to/local/repo
  go run . --log-level DEBUG --output report.json https://github.com/OWNER/REPO.git
  go run . --token-names "BOT_TOKEN MYBOT_TOKEN MAXBOT_TOKEN ..." https://github.com/OWNER/REPO.git

Flags:
  -clone-dir string
    	Directory to clone repo into (must be empty)
  -include-node-modules
    	Include findings in node_modules paths
  -keep-clone
    	Keep cloned repository directory
  -local-repo string
    	Path to local git repository (alternative to <repo_url>)
  -log-level string
    	Log level: INFO or DEBUG (default "INFO")
  -o string
    	Path to output JSON report
  -output string
    	Path to output JSON report
  -skip-heuristics
    	Skip custom token heuristics scan (git history)
  -skip-gitleaks
    	Skip gitleaks scan
  -skip-trufflehog
    	Skip trufflehog scan
  -token-names string
    	Token variable names string (comma/space/newline/semicolon separated). Empty means load from pkg/token_names.json
  -heuristic-min-token-length int
    	Minimum token length for heuristic detection (default 24)
  -timeout int
    	Timeout in seconds per scanner command (default 1800)
`)
}
