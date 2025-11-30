package scanner

import (
	"encoding/json"
	"path"
	"strings"

	"github.com/rslater/muaddib/internal/github"
	"github.com/rslater/muaddib/internal/vuln"
)

// VulnerablePackage represents a package found to be vulnerable
type VulnerablePackage struct {
	Package   *Package
	VulnEntry *vuln.VulnEntry
	FilePath  string
	RepoName  string
}

// MaliciousWorkflow represents a detected malicious GitHub Actions workflow
type MaliciousWorkflow struct {
	FilePath string
	RepoName string
	Pattern  string // The malicious pattern detected
}

// MaliciousScript represents a detected malicious script in package.json
type MaliciousScript struct {
	FilePath   string
	RepoName   string
	ScriptName string // e.g., "postinstall"
	Command    string // The actual command
	Pattern    string // The pattern that matched
}

// MaliciousRepo represents a detected malicious repository (migration repo)
type MaliciousRepo struct {
	RepoName    string
	Description string
}

// MaliciousBranch represents a detected malicious branch
type MaliciousBranch struct {
	RepoName   string
	BranchName string
}

// RepoScanResult represents the scan results for a single repository
type RepoScanResult struct {
	RepoName           string
	TotalPackages      int
	VulnerablePackages []*VulnerablePackage
	MaliciousWorkflows []*MaliciousWorkflow
	MaliciousScripts   []*MaliciousScript
	MaliciousBranches  []*MaliciousBranch
	FilesScanned       int
	Error              error
}

// OrgScanResult represents additional scan results at the org/user level
type OrgScanResult struct {
	MaliciousRepos []*MaliciousRepo
}

// Scanner scans repositories for vulnerable packages
type Scanner struct {
	db         *vuln.VulnDB
	includeDev bool
}

// NewScanner creates a new scanner with the given vulnerability database
func NewScanner(db *vuln.VulnDB, includeDev bool) *Scanner {
	return &Scanner{
		db:         db,
		includeDev: includeDev,
	}
}

// ScanFiles scans a list of package files for vulnerable packages
func (s *Scanner) ScanFiles(files []*github.PackageFile) *RepoScanResult {
	if len(files) == 0 {
		return &RepoScanResult{}
	}

	result := &RepoScanResult{
		RepoName:     files[0].RepoName,
		FilesScanned: len(files),
	}

	seen := make(map[string]bool)

	for _, file := range files {
		packages, err := s.parseFile(file)
		if err != nil {
			// Continue scanning other files even if one fails
			continue
		}

		for _, pkg := range packages {
			// Track unique packages
			key := pkg.Name + "@" + pkg.Version
			if !seen[key] {
				seen[key] = true
				result.TotalPackages++
			}

			// Check for vulnerability
			if vulnEntry := s.db.Check(pkg.Name, pkg.Version); vulnEntry != nil {
				result.VulnerablePackages = append(result.VulnerablePackages, &VulnerablePackage{
					Package:   pkg,
					VulnEntry: vulnEntry,
					FilePath:  file.Path,
					RepoName:  file.RepoName,
				})
			}
		}
	}

	// Check for malicious scripts in package.json files
	result.MaliciousScripts = s.CheckPackageScripts(files)

	return result
}

// parseFile parses a package file and returns the list of packages
func (s *Scanner) parseFile(file *github.PackageFile) ([]*Package, error) {
	filename := path.Base(file.Path)

	switch filename {
	case "package.json":
		return ParsePackageJSON(file.Content, s.includeDev)
	case "package-lock.json", "npm-shrinkwrap.json":
		return ParsePackageLock(file.Content, s.includeDev)
	case "yarn.lock":
		return ParseYarnLock(file.Content, s.includeDev)
	case "pnpm-lock.yaml":
		return ParsePnpmLock(file.Content, s.includeDev)
	default:
		return nil, nil
	}
}

// MaliciousWorkflowPattern is the pattern that indicates the Shai-Hulud worm in workflow files
const MaliciousWorkflowPattern = `echo ${{ github.event.discussion.body }}`

// MaliciousScriptPatterns are patterns that indicate the Shai-Hulud worm in package.json scripts
// These are checked against lifecycle scripts like postinstall, preinstall, etc.
var MaliciousScriptPatterns = []string{
	"node bundle.js",
	"setup_bun.js",
	"bun_environment.js",
}

// LifecycleScripts are npm scripts that run automatically and are commonly abused
var LifecycleScripts = []string{
	"preinstall",
	"install",
	"postinstall",
	"preuninstall",
	"uninstall",
	"postuninstall",
	"prepublish",
	"preprepare",
	"prepare",
	"postprepare",
}

// CheckWorkflows scans workflow files for malicious patterns
func (s *Scanner) CheckWorkflows(workflows []*github.WorkflowFile) []*MaliciousWorkflow {
	var malicious []*MaliciousWorkflow

	for _, wf := range workflows {
		if strings.Contains(wf.Content, MaliciousWorkflowPattern) {
			malicious = append(malicious, &MaliciousWorkflow{
				FilePath: wf.Path,
				RepoName: wf.RepoName,
				Pattern:  MaliciousWorkflowPattern,
			})
		}
	}

	return malicious
}

// CheckPackageScripts scans package.json files for malicious scripts
func (s *Scanner) CheckPackageScripts(files []*github.PackageFile) []*MaliciousScript {
	var malicious []*MaliciousScript

	for _, file := range files {
		// Only check package.json files (not package-lock.json)
		if !strings.HasSuffix(file.Path, "package.json") || strings.Contains(file.Path, "package-lock") {
			continue
		}

		scripts := extractScripts(file.Content)
		if scripts == nil {
			continue
		}

		// Check each lifecycle script for malicious patterns
		for _, scriptName := range LifecycleScripts {
			command, exists := scripts[scriptName]
			if !exists {
				continue
			}

			for _, pattern := range MaliciousScriptPatterns {
				if strings.Contains(command, pattern) {
					malicious = append(malicious, &MaliciousScript{
						FilePath:   file.Path,
						RepoName:   file.RepoName,
						ScriptName: scriptName,
						Command:    command,
						Pattern:    pattern,
					})
				}
			}
		}
	}

	return malicious
}

// extractScripts extracts the scripts section from package.json
func extractScripts(content string) map[string]string {
	var pkg struct {
		Scripts map[string]string `json:"scripts"`
	}

	if err := json.Unmarshal([]byte(content), &pkg); err != nil {
		return nil
	}

	return pkg.Scripts
}
