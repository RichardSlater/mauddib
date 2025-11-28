package reporter

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/rslater/muaddib/internal/scanner"
)

// TerminalReporter outputs scan results to the terminal with colors and emoji
type TerminalReporter struct {
	out          io.Writer
	verbose      bool
	headerColor  *color.Color
	errorColor   *color.Color
	warnColor    *color.Color
	successColor *color.Color
	infoColor    *color.Color
	dimColor     *color.Color
}

// ReporterOption configures the TerminalReporter
type ReporterOption func(*TerminalReporter)

// WithOutput sets the output writer
func WithOutput(w io.Writer) ReporterOption {
	return func(r *TerminalReporter) {
		r.out = w
	}
}

// WithVerbose enables verbose output
func WithVerbose(v bool) ReporterOption {
	return func(r *TerminalReporter) {
		r.verbose = v
	}
}

// NewTerminalReporter creates a new terminal reporter
func NewTerminalReporter(opts ...ReporterOption) *TerminalReporter {
	r := &TerminalReporter{
		out:          os.Stdout,
		headerColor:  color.New(color.FgMagenta, color.Bold),
		errorColor:   color.New(color.FgRed, color.Bold),
		warnColor:    color.New(color.FgYellow),
		successColor: color.New(color.FgGreen),
		infoColor:    color.New(color.FgWhite),
		dimColor:     color.New(color.FgHiBlack),
	}

	for _, opt := range opts {
		opt(r)
	}

	return r
}

// ReportProgress reports a progress message
func (r *TerminalReporter) ReportProgress(message string) {
	r.dimColor.Fprintf(r.out, "%s\n", message)
}

// ReportRepoStart reports the start of scanning a repository
func (r *TerminalReporter) ReportRepoStart(repoName string) {
	r.headerColor.Fprintf(r.out, "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	r.headerColor.Fprintf(r.out, "📁 Repository: %s\n", repoName)
	r.headerColor.Fprintf(r.out, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
}

// ReportRepoResult reports the results for a single repository
func (r *TerminalReporter) ReportRepoResult(result *scanner.RepoScanResult) {
	if result.Error != nil {
		r.errorColor.Fprintf(r.out, "❌ Error scanning repository: %v\n", result.Error)
		return
	}

	// If no files scanned and no malicious branches, nothing to report
	if result.FilesScanned == 0 && len(result.MaliciousBranches) == 0 {
		return
	}

	if result.FilesScanned > 0 {
		r.infoColor.Fprintf(r.out, "📦 Scanned %d files, found %d unique packages\n",
			result.FilesScanned, result.TotalPackages)
	}

	if !r.resultHasIssues(result) {
		r.successColor.Fprintf(r.out, "✅ No vulnerable packages or malicious patterns detected\n")
		return
	}

	vulnCount := len(result.VulnerablePackages) + len(result.MaliciousWorkflows) +
		len(result.MaliciousScripts) + len(result.MaliciousBranches)
	r.errorColor.Fprintf(r.out, "🔴 Found %d issue(s):\n\n", vulnCount)

	r.reportMaliciousBranches(result.MaliciousBranches)
	r.reportMaliciousWorkflows(result.MaliciousWorkflows)
	r.reportMaliciousScripts(result.MaliciousScripts)
	r.reportVulnerablePackages(result.VulnerablePackages)
}

// resultHasIssues checks if a result contains any issues
func (r *TerminalReporter) resultHasIssues(result *scanner.RepoScanResult) bool {
	return len(result.VulnerablePackages) > 0 ||
		len(result.MaliciousWorkflows) > 0 ||
		len(result.MaliciousScripts) > 0 ||
		len(result.MaliciousBranches) > 0
}

// reportMaliciousBranches outputs malicious branch detections
func (r *TerminalReporter) reportMaliciousBranches(branches []*scanner.MaliciousBranch) {
	if len(branches) == 0 {
		return
	}
	r.errorColor.Fprintf(r.out, "  🌿 Malicious Branch Detected:\n")
	for _, mb := range branches {
		r.errorColor.Fprintf(r.out, "     🔴 Branch: %s\n", mb.BranchName)
	}
	fmt.Fprintln(r.out)
}

// reportMaliciousWorkflows outputs malicious workflow detections
func (r *TerminalReporter) reportMaliciousWorkflows(workflows []*scanner.MaliciousWorkflow) {
	if len(workflows) == 0 {
		return
	}
	r.errorColor.Fprintf(r.out, "  🐛 Malicious Workflow Detected:\n")
	for _, mw := range workflows {
		r.errorColor.Fprintf(r.out, "     🔴 %s\n", mw.FilePath)
		r.dimColor.Fprintf(r.out, "        Pattern: %s\n", mw.Pattern)
	}
	fmt.Fprintln(r.out)
}

// reportMaliciousScripts outputs malicious script detections
func (r *TerminalReporter) reportMaliciousScripts(scripts []*scanner.MaliciousScript) {
	if len(scripts) == 0 {
		return
	}
	r.errorColor.Fprintf(r.out, "  💉 Malicious Script Detected:\n")
	for _, ms := range scripts {
		r.errorColor.Fprintf(r.out, "     🔴 %s\n", ms.FilePath)
		r.dimColor.Fprintf(r.out, "        Script: %s → %s\n", ms.ScriptName, ms.Command)
		r.dimColor.Fprintf(r.out, "        Pattern: %s\n", ms.Pattern)
	}
	fmt.Fprintln(r.out)
}

// reportVulnerablePackages outputs vulnerable package detections grouped by file
func (r *TerminalReporter) reportVulnerablePackages(packages []*scanner.VulnerablePackage) {
	if len(packages) == 0 {
		return
	}

	// Group by file
	byFile := make(map[string][]*scanner.VulnerablePackage)
	for _, vp := range packages {
		byFile[vp.FilePath] = append(byFile[vp.FilePath], vp)
	}

	for filePath, vulns := range byFile {
		r.warnColor.Fprintf(r.out, "  📄 %s:\n", filePath)
		for _, vp := range vulns {
			r.reportSingleVulnerablePackage(vp)
		}
		fmt.Fprintln(r.out)
	}
}

// reportSingleVulnerablePackage outputs a single vulnerable package entry
func (r *TerminalReporter) reportSingleVulnerablePackage(vp *scanner.VulnerablePackage) {
	devMarker := ""
	if vp.Package.IsDev {
		devMarker = r.dimColor.Sprint(" (dev)")
	}
	sourceMarker := ""
	if vp.Package.Source == "transitive" {
		sourceMarker = r.dimColor.Sprint(" [transitive]")
	}

	r.errorColor.Fprintf(r.out, "     🔴 %s@%s%s%s\n",
		vp.Package.Name,
		vp.Package.Version,
		devMarker,
		sourceMarker)

	if vp.VulnEntry.PackageVersion != "" && vp.VulnEntry.PackageVersion != vp.Package.Version {
		r.dimColor.Fprintf(r.out, "        ⚠️  IOC version: %s\n", vp.VulnEntry.PackageVersion)
	}
}

// ReportMaliciousRepo reports a detected malicious migration repository
func (r *TerminalReporter) ReportMaliciousRepo(repoName, description string) {
	r.errorColor.Fprintf(r.out, "🚨 MALICIOUS MIGRATION REPO DETECTED: %s\n", repoName)
	r.dimColor.Fprintf(r.out, "   Description: %s\n", description)
	r.dimColor.Fprintf(r.out, "   This repo was likely created by the Shai-Hulud worm and may contain exposed secrets!\n\n")
}

// summaryStats holds aggregated statistics for the scan summary
type summaryStats struct {
	totalRepos              int
	totalPackages           int
	totalVulnerable         int
	totalMaliciousWorkflows int
	totalMaliciousScripts   int
	totalMaliciousBranches  int
	totalMaliciousRepos     int
	reposWithVulns          int
	errorCount              int
}

// calculateSummaryStats aggregates statistics from scan results
func (r *TerminalReporter) calculateSummaryStats(results []*scanner.RepoScanResult, orgResult *scanner.OrgScanResult) summaryStats {
	stats := summaryStats{totalRepos: len(results)}

	if orgResult != nil {
		stats.totalMaliciousRepos = len(orgResult.MaliciousRepos)
	}

	for _, result := range results {
		if result.Error != nil {
			stats.errorCount++
			continue
		}
		stats.totalPackages += result.TotalPackages
		if r.resultHasIssues(result) {
			stats.totalVulnerable += len(result.VulnerablePackages)
			stats.totalMaliciousWorkflows += len(result.MaliciousWorkflows)
			stats.totalMaliciousScripts += len(result.MaliciousScripts)
			stats.totalMaliciousBranches += len(result.MaliciousBranches)
			stats.reposWithVulns++
		}
	}

	return stats
}

// hasAnyIssues checks if any issues were found in the summary stats
func (s summaryStats) hasAnyIssues() bool {
	return s.totalVulnerable > 0 || s.totalMaliciousWorkflows > 0 ||
		s.totalMaliciousScripts > 0 || s.totalMaliciousBranches > 0 || s.totalMaliciousRepos > 0
}

// reportSummaryIssues outputs the issue counts in the summary
func (r *TerminalReporter) reportSummaryIssues(stats summaryStats) {
	if stats.totalMaliciousRepos > 0 {
		r.errorColor.Fprintf(r.out, "🚨 Migration repos found:     %d (CRITICAL - secrets may be exposed!)\n", stats.totalMaliciousRepos)
	}
	if stats.totalMaliciousBranches > 0 {
		r.errorColor.Fprintf(r.out, "🌿 Malicious branches found:  %d\n", stats.totalMaliciousBranches)
	}
	if stats.totalVulnerable > 0 {
		r.errorColor.Fprintf(r.out, "🔴 Vulnerable packages found: %d\n", stats.totalVulnerable)
	}
	if stats.totalMaliciousWorkflows > 0 {
		r.errorColor.Fprintf(r.out, "🐛 Malicious workflows found: %d\n", stats.totalMaliciousWorkflows)
	}
	if stats.totalMaliciousScripts > 0 {
		r.errorColor.Fprintf(r.out, "💉 Malicious scripts found:   %d\n", stats.totalMaliciousScripts)
	}
	r.errorColor.Fprintf(r.out, "⚠️  Affected repositories:    %d\n", stats.reposWithVulns+stats.totalMaliciousRepos)
}

// reportAffectedRepos lists all repositories with issues
func (r *TerminalReporter) reportAffectedRepos(results []*scanner.RepoScanResult) {
	r.warnColor.Fprintf(r.out, "Affected repositories:\n")
	for _, result := range results {
		if !r.resultHasIssues(result) {
			continue
		}
		parts := r.buildIssueParts(result)
		r.errorColor.Fprintf(r.out, "  🔴 %s (%s)\n", result.RepoName, strings.Join(parts, ", "))
	}
	fmt.Fprintln(r.out)
}

// buildIssueParts creates the issue description parts for a result
func (r *TerminalReporter) buildIssueParts(result *scanner.RepoScanResult) []string {
	var parts []string
	if len(result.MaliciousBranches) > 0 {
		parts = append(parts, fmt.Sprintf("%d malicious branch", len(result.MaliciousBranches)))
	}
	if len(result.VulnerablePackages) > 0 {
		parts = append(parts, fmt.Sprintf("%d vulnerable", len(result.VulnerablePackages)))
	}
	if len(result.MaliciousWorkflows) > 0 {
		parts = append(parts, fmt.Sprintf("%d malicious workflow", len(result.MaliciousWorkflows)))
	}
	if len(result.MaliciousScripts) > 0 {
		parts = append(parts, fmt.Sprintf("%d malicious script", len(result.MaliciousScripts)))
	}
	return parts
}

// ReportSummary reports the overall scan summary
func (r *TerminalReporter) ReportSummary(results []*scanner.RepoScanResult, orgResult *scanner.OrgScanResult, vulnDBSize int) {
	fmt.Fprintln(r.out)
	r.headerColor.Fprintf(r.out, "══════════════════════════════════════════════════════════════\n")
	r.headerColor.Fprintf(r.out, "                        SCAN SUMMARY\n")
	r.headerColor.Fprintf(r.out, "══════════════════════════════════════════════════════════════\n\n")

	stats := r.calculateSummaryStats(results, orgResult)

	r.infoColor.Fprintf(r.out, "📊 Repositories scanned:     %d\n", stats.totalRepos)
	r.infoColor.Fprintf(r.out, "📦 Total packages checked:   %d\n", stats.totalPackages)
	r.infoColor.Fprintf(r.out, "🔍 IOC database entries:     %d\n", vulnDBSize)
	fmt.Fprintln(r.out)

	if stats.hasAnyIssues() {
		r.reportSummaryIssues(stats)
	} else {
		r.successColor.Fprintf(r.out, "✅ No vulnerable packages or malicious patterns detected!\n")
	}

	if stats.errorCount > 0 {
		r.warnColor.Fprintf(r.out, "⚠️  Repositories with errors: %d\n", stats.errorCount)
	}

	fmt.Fprintln(r.out)

	if stats.totalMaliciousRepos > 0 {
		r.errorColor.Fprintf(r.out, "🚨 CRITICAL - Malicious migration repositories:\n")
		for _, repo := range orgResult.MaliciousRepos {
			r.errorColor.Fprintf(r.out, "  🚨 %s\n", repo.RepoName)
		}
		fmt.Fprintln(r.out)
	}

	if stats.reposWithVulns > 0 {
		r.reportAffectedRepos(results)
	}

	r.headerColor.Fprintf(r.out, "══════════════════════════════════════════════════════════════\n")
}

// ReportError reports an error
func (r *TerminalReporter) ReportError(format string, args ...interface{}) {
	r.errorColor.Fprintf(r.out, "❌ "+format+"\n", args...)
}

// ReportWarning reports a warning message
func (r *TerminalReporter) ReportWarning(format string, args ...interface{}) {
	r.warnColor.Fprintf(r.out, format+"\n", args...)
}

// ReportInfo reports an informational message
func (r *TerminalReporter) ReportInfo(format string, args ...interface{}) {
	r.infoColor.Fprintf(r.out, format+"\n", args...)
}

// ReportSuccess reports a success message
func (r *TerminalReporter) ReportSuccess(format string, args ...interface{}) {
	r.successColor.Fprintf(r.out, "✅ "+format+"\n", args...)
}

// PrintBanner prints the application banner
func (r *TerminalReporter) PrintBanner() {
	banner := `
  __  __                 _  _     _  _  _
 |  \/  | _  _   __ _  __| |( ) __| |(_)| |__
 | |\/| || || | / _` + "`" + ` |/ _` + "`" + ` ||/ / _` + "`" + ` || || '_ \
 | |  | || _,_|| (_| || (_| |  | (_| || || |_) |
 |_|  |_| \__,_|\__,_| \__,_|   \__,_||_||_.__/

   Shai-Hulud NPM Worm Scanner for GitHub
`
	r.headerColor.Fprintln(r.out, banner)
	fmt.Fprintln(r.out, strings.Repeat("─", 60))
}
