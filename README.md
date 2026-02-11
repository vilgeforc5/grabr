# grabr

`grabr` scans git repositories for potential leaked secrets using `gitleaks`, `trufflehog`, and heuristic checks.

## Usage

```text
grabr [flags] <repo_url>
grabr [flags] --local-repo <path>
grabr help
```

## Examples

```bash
go run . https://github.com/OWNER/REPO.git
go run . --local-repo /path/to/local/repo
go run . --log-level DEBUG --output report.json https://github.com/OWNER/REPO.git
go run . --token-names "BOT_TOKEN MYBOT_TOKEN MAXBOT_TOKEN ..." https://github.com/OWNER/REPO.git
```

## Flags

```text
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
    Skip custom token heuristics scan
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
```
