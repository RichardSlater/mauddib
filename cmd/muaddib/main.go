package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/rslater/muaddib/internal/github"
	"github.com/rslater/muaddib/internal/reporter"
	"github.com/rslater/muaddib/internal/scanner"
	"github.com/rslater/muaddib/internal/vuln"
)

var (
	org       string
	user      string
	vulnCSV   string
	rateLimit float64
	skipDev   bool
	verbose   bool
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "muaddib",
		Short: "NPM vulnerability scanner for GitHub repositories",
		Long: `Muaddib scans GitHub organization or user repositories for vulnerable npm packages.

It fetches package.json and package-lock.json files from all repositories,
extracts all dependencies (including transitive), and checks them against
a vulnerability database (IOC list).

Environment Variables:
  GITHUB_TOKEN    Required. GitHub Personal Access Token for API access.

Example:
  export GITHUB_TOKEN=ghp_xxxxxxxxxxxx
  muaddib --org mycompany
  muaddib --user johndoe --vuln-csv ./my-iocs.csv`,
		RunE: run,
	}

	rootCmd.Flags().StringVar(&org, "org", "", "GitHub organization to scan")
	rootCmd.Flags().StringVar(&user, "user", "", "GitHub user to scan")
	rootCmd.Flags().StringVar(&vulnCSV, "vuln-csv", "", "Path or URL to vulnerability CSV (default: DataDog IOC list)")
	rootCmd.Flags().Float64Var(&rateLimit, "rate-limit", 1.0, "API requests per second (lower is safer)")
	rootCmd.Flags().BoolVar(&skipDev, "skip-dev", false, "Skip devDependencies")
	rootCmd.Flags().BoolVar(&verbose, "verbose", false, "Enable verbose output")

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// validateFlags checks that exactly one of --org or --user is specified
func validateFlags() error {
	if org == "" && user == "" {
		return fmt.Errorf("either --org or --user must be specified")
	}
	if org != "" && user != "" {
		return fmt.Errorf("--org and --user are mutually exclusive")
	}
	return nil
}

// setupContext creates a context with cancellation and signal handling
func setupContext(rep *reporter.TerminalReporter) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		rep.ReportInfo("\n⚠️  Interrupt received, shutting down gracefully...")
		cancel()
	}()

	return ctx, cancel
}

// loadVulnDB loads the vulnerability database from the configured source
func loadVulnDB(rep *reporter.TerminalReporter) (*vuln.VulnDB, error) {
	rep.ReportInfo("📥 Loading vulnerability database...")

	vuln.SetWarningFunc(func(msg string) {
		rep.ReportWarning("⚠️  %s", msg)
	})

	if vulnCSV != "" {
		rep.ReportInfo("   Using custom source: %s", vulnCSV)
		if strings.HasPrefix(vulnCSV, "http://") || strings.HasPrefix(vulnCSV, "https://") {
			return vuln.LoadFromURL(vulnCSV)
		}
		return vuln.LoadFromFile(vulnCSV)
	}

	rep.ReportInfo("   Using default sources: DataDog + Wiz IOC lists")
	return vuln.LoadFromMultipleURLs(vuln.DefaultIOCURLs())
}

// createGitHubClient creates and configures the GitHub API client
func createGitHubClient(rep *reporter.TerminalReporter) (*github.Client, error) {
	progressCb := func(msg string) {
		if verbose {
			rep.ReportProgress(msg)
		}
	}

	return github.NewClientFromEnv(
		github.WithRateLimit(rateLimit),
		github.WithProgressCallback(progressCb),
	)
}

// listRepositories fetches repositories for the configured org or user
func listRepositories(ctx context.Context, ghClient *github.Client, rep *reporter.TerminalReporter) ([]*github.Repository, error) {
	if org != "" {
		rep.ReportInfo("📦 Fetching repositories for organization: %s", org)
		return ghClient.ListOrgRepos(ctx, org)
	}
	rep.ReportInfo("📦 Fetching repositories for user: %s", user)
	return ghClient.ListUserRepos(ctx, user)
}

// checkMaliciousMigrationRepos checks all repos for malicious migration patterns
func checkMaliciousMigrationRepos(repos []*github.Repository, rep *reporter.TerminalReporter) *scanner.OrgScanResult {
	rep.ReportInfo("🔍 Checking for malicious migration repositories...")
	var orgResult scanner.OrgScanResult

	for _, repo := range repos {
		if github.IsMaliciousMigrationRepo(repo) {
			orgResult.MaliciousRepos = append(orgResult.MaliciousRepos, &scanner.MaliciousRepo{
				RepoName:    repo.FullName,
				Description: repo.Description,
			})
			rep.ReportMaliciousRepo(repo.FullName, repo.Description)
		}
	}

	if len(orgResult.MaliciousRepos) == 0 {
		rep.ReportSuccess("No malicious migration repositories found")
	}
	return &orgResult
}

// scanRepository scans a single repository for vulnerabilities and malicious patterns
func scanRepository(
	ctx context.Context,
	repo *github.Repository,
	ghClient *github.Client,
	scan *scanner.Scanner,
	rep *reporter.TerminalReporter,
) *scanner.RepoScanResult {
	files, err := ghClient.FindPackageFiles(ctx, repo)
	if err != nil {
		return &scanner.RepoScanResult{RepoName: repo.FullName, Error: err}
	}

	result := scan.ScanFiles(files)

	// Check workflows
	workflows, err := ghClient.FindMaliciousWorkflows(ctx, repo)
	if err != nil && verbose {
		rep.ReportProgress(fmt.Sprintf("   ⚠️  Failed to check workflows: %v", err))
	} else if len(workflows) > 0 {
		result.MaliciousWorkflows = scan.CheckWorkflows(workflows)
	}

	// Check branches
	if verbose {
		rep.ReportProgress(fmt.Sprintf("🌿 Checking %s for malicious branches...", repo.FullName))
	}
	maliciousBranches, err := ghClient.FindMaliciousBranches(ctx, repo)
	if err != nil && verbose {
		rep.ReportProgress(fmt.Sprintf("   ⚠️  Failed to check branches: %v", err))
	} else {
		if verbose && len(maliciousBranches) == 0 {
			rep.ReportProgress("   ✓ No malicious branches found")
		}
		for _, branch := range maliciousBranches {
			result.MaliciousBranches = append(result.MaliciousBranches, &scanner.MaliciousBranch{
				RepoName:   branch.RepoName,
				BranchName: branch.Name,
			})
		}
	}

	return result
}

// resultHasIssues checks if a scan result contains any issues
func resultHasIssues(result *scanner.RepoScanResult) bool {
	return len(result.VulnerablePackages) > 0 ||
		len(result.MaliciousWorkflows) > 0 ||
		len(result.MaliciousScripts) > 0 ||
		len(result.MaliciousBranches) > 0
}

func run(cmd *cobra.Command, args []string) error {
	rep := reporter.NewTerminalReporter(reporter.WithVerbose(verbose))
	rep.PrintBanner()

	if err := validateFlags(); err != nil {
		return err
	}

	ctx, cancel := setupContext(rep)
	defer cancel()

	db, err := loadVulnDB(rep)
	if err != nil {
		return fmt.Errorf("failed to load vulnerability database: %w", err)
	}
	rep.ReportSuccess("Loaded %d IOC entries (%d unique packages, %d vulnerable versions)",
		db.TotalEntries(), db.UniquePackages(), db.Size())

	ghClient, err := createGitHubClient(rep)
	if err != nil {
		return err
	}
	rep.ReportInfo("🔗 Connected to GitHub API (rate limit: %.1f req/sec)", rateLimit)

	repos, err := listRepositories(ctx, ghClient, rep)
	if err != nil {
		return fmt.Errorf("failed to list repositories: %w", err)
	}

	if len(repos) == 0 {
		rep.ReportInfo("No repositories found")
		return nil
	}
	rep.ReportSuccess("Found %d repositories", len(repos))

	orgResult := checkMaliciousMigrationRepos(repos, rep)
	scan := scanner.NewScanner(db, !skipDev)

	var results []*scanner.RepoScanResult
	for i, repo := range repos {
		select {
		case <-ctx.Done():
			rep.ReportInfo("Scan interrupted, showing partial results...")
			goto summary
		default:
		}

		if repo.Archived {
			rep.ReportInfo("🔍 [%d/%d] Scanning %s...", i+1, len(repos), repo.FullName)
			rep.ReportProgress("   ⏭️  Skipping archived repository")
			continue
		}

		if verbose {
			rep.ReportRepoStart(repo.FullName)
		}
		rep.ReportInfo("🔍 [%d/%d] Scanning %s...", i+1, len(repos), repo.FullName)

		result := scanRepository(ctx, repo, ghClient, scan, rep)
		results = append(results, result)

		hasIssues := resultHasIssues(result)
		if hasIssues && !verbose {
			rep.ReportRepoStart(repo.FullName)
		}
		if verbose || hasIssues {
			rep.ReportRepoResult(result)
		}
	}

summary:
	rep.ReportSummary(results, orgResult, db.Size())
	rep.ReportInfo("📊 Total API requests made: %d", ghClient.GetRequestsMade())

	return nil
}
