# AGENTS.md - AI Agent Instructions for Muaddib

This document provides context and guidelines for AI coding agents working on this project.

## Project Overview

Muaddib is a Go CLI tool that scans GitHub organizations/users for npm packages affected by the Shai-Hulud supply chain attack. It fetches package manifest and lock files via the GitHub API and matches dependencies against an IOC (Indicators of Compromise) database. It also detects malicious GitHub Actions workflows created by the worm.

## Supported Package Managers

- **npm**: `package.json`, `package-lock.json`, `npm-shrinkwrap.json`
- **Yarn Classic (v1)**: `yarn.lock` (Yarn Berry/v2+ is detected and returns an error)
- **pnpm**: `pnpm-lock.yaml` (v6+ and v9+ formats supported)

## Architecture

```text
cmd/muaddib/main.go    → CLI entry point (cobra), orchestrates the scan flow
internal/
├── github/            → GitHub API client with rate limiting & pagination
│   ├── client.go      → Authenticated client with configurable rate limits
│   ├── repos.go       → List org/user repositories
│   └── contents.go    → Fetch package files and workflow files via Git tree API
├── scanner/           → Core scanning logic
│   ├── parser.go      → Parse package.json, package-lock.json, yarn.lock, pnpm-lock.yaml
│   └── matcher.go     → Match packages against VulnDB, detect malicious workflows and scripts
├── vuln/              → Vulnerability database
│   └── loader.go      → Load IOCs from CSV (file or URL), handle version lists
└── reporter/          → Terminal output with colors and emoji
    └── terminal.go    → Colored output, per-repo and summary reports
```

**Data flow:** CLI → GitHub client fetches repos → contents.go finds package files and workflows → scanner parses JSON and checks workflow patterns → matcher checks against VulnDB → reporter outputs results.

## Development Commands

```bash
go build -o muaddib ./cmd/muaddib/    # Build binary
go test ./...                          # Run all tests
go fmt ./...                           # Format code
go vet ./...                           # Static analysis
```

## Code Style & Patterns

### Functional Options Pattern

All major components use functional options for configuration:

```go
// Example from github/client.go
ghClient, err := github.NewClientFromEnv(
    github.WithRateLimit(1.0),
    github.WithProgressCallback(cb),
)
```

### Error Handling

- Continue scanning other files/repos on individual failures
- Aggregate errors in `RepoScanResult.Error`
- Support graceful shutdown via context cancellation

### Package Lock Parsing

Supports multiple lockfile formats in `parser.go`:

**npm (package-lock.json / npm-shrinkwrap.json):**
- v2/v3: Uses `packages` field with `node_modules/` paths
- v1 (legacy): Uses nested `dependencies` field with recursive parsing

**pnpm (pnpm-lock.yaml):**
- v6-v8: Package keys with leading slash (e.g., `/pkg@1.0.0`)
- v9+: Package keys without leading slash (e.g., `pkg@1.0.0`)
- Peer dependency suffixes are stripped (e.g., `1.0.0(peer@2.0.0)` → `1.0.0`)

**Yarn (yarn.lock):**
- Only Yarn Classic (v1) format is supported
- Yarn Berry (v2+) format is detected and returns an error
- Note: `--skip-dev` flag has no effect on yarn.lock (format doesn't track dev dependencies)

## Testing Guidelines

### Test Data Naming Convention

**IMPORTANT:** Use `test-muaddib-*` prefix for fake package names in tests to avoid matching real IOCs:

```go
// CORRECT
"test-muaddib-pkg-a": "1.0.0",
"test-muaddib-vulnerable": "1.0.0",

// WRONG - may conflict with real IOCs
"some-package": "1.0.0",
```

### CSV IOC Format (Critical)

The vulnerability database supports two CSV formats:

#### DataDog Format

```csv
package_name,package_versions,sources
@scope/package,1.0.0,"datadog, wiz"
multi-version-pkg,"1.0.0, 1.0.1, 1.0.2","datadog"
```

#### Wiz Format (npm semver specification)

```csv
Package,Version
@scope/package,= 1.0.0
multi-version-pkg,= 1.0.0 || = 1.0.1 || = 1.0.2
```

**Key parsing behaviors in `loader.go`:**

- Column names are case-insensitive (`package_name`, `PackageName`, `name`, `package` all work)
- DataDog `package_versions` can be comma-separated: `"1.0.0, 1.0.1"` expands to separate entries
- Wiz `Version` uses npm semver spec: `= 1.0.0 || = 2.0.0` expands to separate entries
- Entries without versions are **skipped** (both name AND version required for matching)
- Scoped packages like `@scope/pkg` are fully supported
- **Default behavior**: Loads BOTH DataDog AND Wiz IOC lists, merged and deduplicated
- **Flexible column detection**: If headers are not recognized, falls back to positional parsing (column 1 = package name, column 2 = version) with a warning

**Test CSV format examples:**

```go
// DataDog format
csvData := `package_name,package_versions,sources
test-muaddib-vulnerable,1.0.0,"test"`

// Wiz format
csvData := `Package,Version
test-muaddib-vulnerable,= 1.0.0`

// Unknown headers (will use fallback with warning)
csvData := `pkg,ver,extra
test-muaddib-vulnerable,1.0.0,"test"`
csvData := `wrong_column,version
test-pkg,1.0.0`
```

### Test Helpers

Use `vuln.ParseCSVForTest()` to create test vulnerability databases:

```go
csvData := `package_name,package_versions,sources
test-muaddib-vulnerable,1.0.0,"test"`
db, err := vuln.ParseCSVForTest(strings.NewReader(csvData))
```

Use predefined test constants pattern from `loader_test.go`:

```go
const (
    testPkgVulnerable1  = "test-muaddib-vulnerable-pkg-1"
    testPkgScoped       = "@test-muaddib/vulnerable-scoped"
)
```

### Running Tests

```bash
go test ./...           # Run all tests
go test ./internal/...  # Run internal package tests only
go test -v ./...        # Verbose output
go test -race ./...     # Race condition detection
```

## External Dependencies

- `github.com/google/go-github/v67` - GitHub API client
- `github.com/spf13/cobra` - CLI framework
- `golang.org/x/time/rate` - Rate limiting
- `github.com/fatih/color` - Terminal colors

## Environment Variables

- `GITHUB_TOKEN` (required) - GitHub token with `Contents: Read` and `Metadata: Read` permissions

## Important Edge Cases

- **Archived repos**: Skipped automatically in `main.go`
- **Empty repos**: Returns `nil` files gracefully in `contents.go` (HTTP 409/404)
- **Rate limiting**: Built-in with configurable RPS, automatic retry on limits
- **Context cancellation**: Graceful shutdown with partial results via `goto summary`

## Malicious Pattern Detection

The scanner detects multiple Shai-Hulud worm indicators:

### Malicious Migration Repositories

The worm creates public copies of private repositories with exposed secrets:

- **Repository name pattern**: `*-migration` suffix (e.g., `myrepo-migration`)
- **Description**: `Shai-Hulud Migration`

These repos are detected at the org/user level before individual repo scanning.

### Malicious Branches

- **Branch name**: `shai-hulud`

The worm creates this branch in compromised repositories.

### Malicious Workflows

- **File**: `.github/workflows/discussion.yaml`
- **Pattern**: `echo ${{ github.event.discussion.body }}`

This workflow is used by the worm to execute arbitrary code via GitHub Discussions.

### Malicious npm Lifecycle Scripts

The scanner checks `package.json` for malicious scripts in npm lifecycle hooks:

- **Lifecycle scripts checked**: `preinstall`, `install`, `postinstall`, `preuninstall`, `uninstall`, `postuninstall`, `prepublish`, `preprepare`, `prepare`, `postprepare`
- **Pattern**: `node bundle.js`

Example of a malicious package.json:

```json
{
  "scripts": {
    "postinstall": "node bundle.js"
  }
}
```

All patterns are detected using simple string matching in `scanner/matcher.go` and `github/repos.go`.

## Common Pitfalls to Avoid

1. **Don't use generic package names in tests** - Always use `test-muaddib-*` prefix
2. **Don't assume CSV column order** - Parser uses column names, not positions
3. **Don't forget version in IOC entries** - Entries without versions are skipped
4. **Don't ignore context cancellation** - Always check `ctx.Err()` in loops
5. **Don't make parallel GitHub API calls without rate limiting** - Use the client's built-in limiter

## Pre-commit Hooks

This project uses [pre-commit](https://pre-commit.com/) to ensure code quality. Install with:

```bash
pip install pre-commit
pre-commit install
```

## File Modification Guidelines

When modifying files:

1. Run `go fmt ./...` after changes
2. Run `go vet ./...` to catch issues
3. Run `go test ./...` to verify nothing broke
4. Follow existing patterns in the codebase
