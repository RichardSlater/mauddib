package scanner

import (
	"encoding/json"
	"fmt"
	"gopkg.in/yaml.v3"
	"strings"
)

// Package represents a package with name and version
type Package struct {
	Name    string
	Version string
	IsDev   bool
	Source  string // "direct" or "transitive"
}

// PackageJSON represents the structure of a package.json file
type PackageJSON struct {
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
}

// PackageLockJSON represents the structure of a package-lock.json file (v2/v3)
type PackageLockJSON struct {
	Name            string                      `json:"name"`
	Version         string                      `json:"version"`
	LockfileVersion int                         `json:"lockfileVersion"`
	Packages        map[string]PackageLockEntry `json:"packages"`     // v2/v3 format
	Dependencies    map[string]LegacyLockEntry  `json:"dependencies"` // v1 format
}

// PackageLockEntry represents an entry in the packages map (v2/v3)
type PackageLockEntry struct {
	Version      string            `json:"version"`
	Resolved     string            `json:"resolved"`
	Dev          bool              `json:"dev"`
	Optional     bool              `json:"optional"`
	Dependencies map[string]string `json:"dependencies"`
}

// LegacyLockEntry represents an entry in the v1 dependencies map
type LegacyLockEntry struct {
	Version      string                     `json:"version"`
	Dev          bool                       `json:"dev"`
	Optional     bool                       `json:"optional"`
	Requires     map[string]string          `json:"requires"`
	Dependencies map[string]LegacyLockEntry `json:"dependencies"`
}

// ParsePackageJSON parses a package.json file and extracts all dependencies
func ParsePackageJSON(content string, includeDev bool) ([]*Package, error) {
	var pkg PackageJSON
	if err := json.Unmarshal([]byte(content), &pkg); err != nil {
		return nil, fmt.Errorf("failed to parse package.json: %w", err)
	}

	var packages []*Package

	// Production dependencies
	for name, version := range pkg.Dependencies {
		packages = append(packages, &Package{
			Name:    name,
			Version: cleanVersion(version),
			IsDev:   false,
			Source:  "direct",
		})
	}

	// Dev dependencies
	if includeDev {
		for name, version := range pkg.DevDependencies {
			packages = append(packages, &Package{
				Name:    name,
				Version: cleanVersion(version),
				IsDev:   true,
				Source:  "direct",
			})
		}
	}

	// Optional dependencies
	for name, version := range pkg.OptionalDependencies {
		packages = append(packages, &Package{
			Name:    name,
			Version: cleanVersion(version),
			IsDev:   false,
			Source:  "direct",
		})
	}

	// Peer dependencies
	for name, version := range pkg.PeerDependencies {
		packages = append(packages, &Package{
			Name:    name,
			Version: cleanVersion(version),
			IsDev:   false,
			Source:  "direct",
		})
	}

	return packages, nil
}

// ParsePackageLock parses a package-lock.json file and extracts all dependencies including transitive
func ParsePackageLock(content string, includeDev bool) ([]*Package, error) {
	var lock PackageLockJSON
	if err := json.Unmarshal([]byte(content), &lock); err != nil {
		return nil, fmt.Errorf("failed to parse package-lock.json: %w", err)
	}

	seen := make(map[string]bool)
	var packages []*Package

	// v2/v3 format uses "packages" field
	if len(lock.Packages) > 0 {
		for pkgPath, entry := range lock.Packages {
			// Skip the root package (empty path or ".")
			if pkgPath == "" || pkgPath == "." {
				continue
			}

			// Skip dev dependencies if not included
			if entry.Dev && !includeDev {
				continue
			}

			name := extractPackageName(pkgPath)
			if name == "" {
				continue
			}

			key := name + "@" + entry.Version
			if seen[key] {
				continue
			}
			seen[key] = true

			packages = append(packages, &Package{
				Name:    name,
				Version: entry.Version,
				IsDev:   entry.Dev,
				Source:  "transitive",
			})
		}
	}

	// v1 format uses "dependencies" field
	if len(lock.Dependencies) > 0 {
		parseLegacyDeps(lock.Dependencies, "", includeDev, seen, &packages)
	}

	return packages, nil
}

// parseLegacyDeps recursively parses v1 format dependencies
func parseLegacyDeps(deps map[string]LegacyLockEntry, prefix string, includeDev bool, seen map[string]bool, packages *[]*Package) {
	for name, entry := range deps {
		// Skip dev dependencies if not included
		if entry.Dev && !includeDev {
			continue
		}

		key := name + "@" + entry.Version
		if seen[key] {
			continue
		}
		seen[key] = true

		*packages = append(*packages, &Package{
			Name:    name,
			Version: entry.Version,
			IsDev:   entry.Dev,
			Source:  "transitive",
		})

		// Recurse into nested dependencies
		if len(entry.Dependencies) > 0 {
			parseLegacyDeps(entry.Dependencies, name+"/", includeDev, seen, packages)
		}
	}
}

// extractPackageName extracts the package name from a package path
// e.g., "node_modules/lodash" -> "lodash"
// e.g., "node_modules/@types/node" -> "@types/node"
// e.g., "node_modules/foo/node_modules/bar" -> "bar"
func extractPackageName(pkgPath string) string {
	// Remove "node_modules/" prefix
	path := strings.TrimPrefix(pkgPath, "node_modules/")

	// Handle nested node_modules (use the last package in the chain)
	parts := strings.Split(path, "/node_modules/")
	lastPart := parts[len(parts)-1]

	// Handle scoped packages (@org/package)
	if strings.HasPrefix(lastPart, "@") {
		// Scoped package: take @scope/name
		segments := strings.SplitN(lastPart, "/", 3)
		if len(segments) >= 2 {
			return segments[0] + "/" + segments[1]
		}
	}

	// Regular package: take first segment
	segments := strings.SplitN(lastPart, "/", 2)
	return segments[0]
}

// cleanVersion removes semver range operators to get a cleaner version
func cleanVersion(version string) string {
	// Remove common prefixes
	version = strings.TrimPrefix(version, "^")
	version = strings.TrimPrefix(version, "~")
	version = strings.TrimPrefix(version, ">=")
	version = strings.TrimPrefix(version, ">")
	version = strings.TrimPrefix(version, "<=")
	version = strings.TrimPrefix(version, "<")
	version = strings.TrimPrefix(version, "=")
	version = strings.TrimSpace(version)

	// Handle ranges like "1.0.0 - 2.0.0", take the first version
	if idx := strings.Index(version, " "); idx > 0 {
		version = version[:idx]
	}

	return version
}

// PnpmLockYAML represents the structure of a pnpm-lock.yaml file (v6+)
type PnpmLockYAML struct {
	LockfileVersion string                   `yaml:"lockfileVersion"`
	Packages        map[string]PnpmLockEntry `yaml:"packages"`
}

// PnpmLockEntry represents an entry in the pnpm packages map
type PnpmLockEntry struct {
	Version      string            `yaml:"version"`
	Resolution   map[string]string `yaml:"resolution"`
	Dev          bool              `yaml:"dev"`
	Optional     bool              `yaml:"optional"`
	Dependencies map[string]string `yaml:"dependencies"`
}

// ParsePnpmLock parses a pnpm-lock.yaml file and returns the list of packages
func ParsePnpmLock(content string, includeDev bool) ([]*Package, error) {
	var lockFile PnpmLockYAML
	if err := yaml.Unmarshal([]byte(content), &lockFile); err != nil {
		return nil, fmt.Errorf("failed to parse pnpm-lock.yaml: %w", err)
	}

	var packages []*Package
	seen := make(map[string]bool)

	// Parse the packages map
	// Keys are in format: /pkg/1.0.0 or /@scope/pkg@1.0.0 or /pkg@1.0.0
	for key, entry := range lockFile.Packages {
		// Skip root package (empty key)
		if key == "" {
			continue
		}

		// Skip dev dependencies if requested
		if entry.Dev && !includeDev {
			continue
		}

		// Extract package name and version from key
		name, version := parsePnpmPackageKey(key)
		if name == "" || version == "" {
			continue
		}

		// Deduplicate
		pkgKey := name + "@" + version
		if seen[pkgKey] {
			continue
		}
		seen[pkgKey] = true

		packages = append(packages, &Package{
			Name:    name,
			Version: version,
			IsDev:   entry.Dev,
			Source:  "transitive",
		})
	}

	return packages, nil
}

// parsePnpmPackageKey extracts package name and version from a pnpm package key
// Examples:
//
//	/pkg/1.0.0 -> (pkg, 1.0.0)
//	/@scope/pkg@1.0.0 -> (@scope/pkg, 1.0.0)
//	/pkg@1.0.0 -> (pkg, 1.0.0)
//	/@scope/pkg/1.0.0 -> (@scope/pkg, 1.0.0)
//	/pkg@1.0.0(peer@2.0.0) -> (pkg, 1.0.0)  // peer dep suffix stripped
//	/pkg@1.0.0_peer@2.0.0 -> (pkg, 1.0.0)   // peer dep suffix stripped
func parsePnpmPackageKey(key string) (name, version string) {
	// Remove leading slash
	key = strings.TrimPrefix(key, "/")

	// Handle scoped packages
	if strings.HasPrefix(key, "@") {
		// Find the @ that separates name from version
		// For @scope/pkg@version, this produces ["", "scope/pkg", "version"]
		// For @scope/pkg/version, this produces ["", "scope/pkg/version"]
		parts := strings.SplitN(key, "@", 3)
		if len(parts) < 2 {
			return "", ""
		}

		scopedName := "@" + parts[1]

		// Check if version is after @ or /
		if len(parts) == 3 {
			// Format: @scope/pkg@version
			return scopedName, stripPnpmPeerDepSuffix(parts[2])
		}

		// Format: @scope/pkg/version - split the original key on last / to get version
		if idx := strings.LastIndex(key, "/"); idx > 0 {
			return key[:idx], stripPnpmPeerDepSuffix(key[idx+1:])
		}

		return "", ""
	}

	// Regular package: pkg@version or pkg/version
	if strings.Contains(key, "@") {
		parts := strings.SplitN(key, "@", 2)
		if len(parts) == 2 {
			return parts[0], stripPnpmPeerDepSuffix(parts[1])
		}
	}

	// Format: pkg/version
	if idx := strings.LastIndex(key, "/"); idx > 0 {
		return key[:idx], stripPnpmPeerDepSuffix(key[idx+1:])
	}

	return "", ""
}

// stripPnpmPeerDepSuffix removes peer dependency suffixes from pnpm versions.
// pnpm lockfiles can include peer dependency info in the version string:
//   - Parentheses format: 1.0.0(peer@2.0.0) or 1.0.0(@scope/peer@2.0.0)
//   - Underscore format: 1.0.0_peer@2.0.0 or 1.0.0_@scope/peer@2.0.0
func stripPnpmPeerDepSuffix(version string) string {
	// Strip parentheses suffix: 1.0.0(peer@2.0.0) -> 1.0.0
	if idx := strings.Index(version, "("); idx > 0 {
		version = version[:idx]
	}

	// Strip underscore suffix: 1.0.0_peer@2.0.0 -> 1.0.0
	// Be careful: version numbers can contain underscores in pre-release tags
	// but pnpm peer dep format always has @ after underscore
	if idx := strings.Index(version, "_"); idx > 0 {
		// Check if this looks like a peer dep suffix (has @ after _)
		suffix := version[idx+1:]
		if strings.Contains(suffix, "@") {
			version = version[:idx]
		}
	}

	return version
}

// ParseYarnLock parses a yarn.lock v1 file and returns the list of packages.
//
// Note: The includeDev parameter is accepted for API consistency but is not used.
// Yarn v1 lockfiles do not distinguish between production and dev dependencies -
// all packages are listed together without a "dev" marker. The --skip-dev flag
// has no effect on yarn.lock files. All packages are marked as IsDev: false.
//
// Yarn Berry (v2+) lockfiles are NOT supported and will return an error with
// a descriptive message. Berry format can be detected by the __metadata: header.
// yarnLockParser holds state for parsing a yarn.lock file
type yarnLockParser struct {
	packages     []*Package
	seen         map[string]bool
	currentNames []string
	currentVer   string
	inEntry      bool
}

// newYarnLockParser creates a new yarn.lock parser
func newYarnLockParser() *yarnLockParser {
	return &yarnLockParser{
		seen: make(map[string]bool),
	}
}

// saveCurrentEntry saves the current package entry if valid
func (p *yarnLockParser) saveCurrentEntry() {
	if !p.inEntry || p.currentVer == "" || len(p.currentNames) == 0 {
		return
	}
	for _, name := range p.currentNames {
		pkgKey := name + "@" + p.currentVer
		if p.seen[pkgKey] {
			continue
		}
		p.seen[pkgKey] = true
		p.packages = append(p.packages, &Package{
			Name:    name,
			Version: p.currentVer,
			IsDev:   false, // yarn.lock v1 doesn't track dev vs prod
			Source:  "transitive",
		})
	}
}

// parseDeclarationLine parses a package declaration line and returns the unique package names
// Format: "pkg@^1.0.0", "pkg@~2.0.0":
func parseYarnDeclarationLine(trimmed string) []string {
	// Remove trailing colon
	namesStr := strings.TrimSuffix(trimmed, ":")
	// Split by comma for multiple ranges
	nameRanges := strings.Split(namesStr, ",")

	var names []string
	seenNames := make(map[string]bool)

	for _, nr := range nameRanges {
		nr = strings.TrimSpace(nr)
		// Remove surrounding quotes (double or single)
		nr = trimSurroundingQuotes(nr)
		// Extract package name (before @)
		name := extractYarnPackageName(nr)
		if name != "" && !seenNames[name] {
			seenNames[name] = true
			names = append(names, name)
		}
	}
	return names
}

// trimSurroundingQuotes removes matching surrounding quotes from a string
func trimSurroundingQuotes(s string) string {
	if strings.HasPrefix(s, "\"") && strings.HasSuffix(s, "\"") {
		return strings.TrimPrefix(strings.TrimSuffix(s, "\""), "\"")
	}
	if strings.HasPrefix(s, "'") && strings.HasSuffix(s, "'") {
		return strings.TrimPrefix(strings.TrimSuffix(s, "'"), "'")
	}
	return s
}

// isYarnDeclarationLine checks if a line is a package declaration (not indented, ends with :)
func isYarnDeclarationLine(line, trimmed string) bool {
	return !strings.HasPrefix(line, " ") &&
		!strings.HasPrefix(line, "\t") &&
		strings.HasSuffix(trimmed, ":")
}

// parseYarnVersionLine extracts version from a "version X" line
func parseYarnVersionLine(trimmed string) string {
	// Format: version "1.0.0"
	parts := strings.SplitN(trimmed, " ", 2)
	if len(parts) == 2 {
		return strings.Trim(parts[1], "\"'")
	}
	return ""
}

// ParseYarnLock parses a yarn.lock v1 file and returns the list of packages.
func ParseYarnLock(content string, includeDev bool) ([]*Package, error) {
	// includeDev is unused: yarn.lock v1 does not distinguish dev dependencies
	_ = includeDev
	// Check for Yarn Berry (v2+) format which is not supported
	if isYarnBerryFormat(content) {
		return nil, fmt.Errorf("yarn.lock appears to be Yarn Berry (v2+) format which is not yet supported; only Yarn Classic (v1) format is supported")
	}

	p := newYarnLockParser()
	lines := strings.Split(content, "\n")

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Skip comments and empty lines
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		// Check if this is a package declaration line
		if isYarnDeclarationLine(line, trimmed) {
			// Save previous entry before starting new one
			p.saveCurrentEntry()

			// Parse new package names (can be multiple version ranges for same package)
			// e.g., "pkg@^1.0.0, pkg@~1.0.5:" - both resolve to the same version
			p.currentNames = parseYarnDeclarationLine(trimmed)
			p.currentVer = ""
			p.inEntry = true
			continue
		}

		// Parse version field
		if p.inEntry && strings.HasPrefix(trimmed, "version") {
			p.currentVer = parseYarnVersionLine(trimmed)
		}
	}

	// Save last entry
	p.saveCurrentEntry()

	return p.packages, nil
}

// extractYarnPackageName extracts the package name from a yarn.lock entry
// Examples:
//
//	"pkg@^1.0.0" -> pkg
//	"@scope/pkg@^1.0.0" -> @scope/pkg
//	"pkg@npm:other@1.0.0" -> pkg
func extractYarnPackageName(entry string) string {
	// Handle npm: aliases
	if strings.Contains(entry, "@npm:") {
		parts := strings.SplitN(entry, "@npm:", 2)
		entry = parts[0]
	}

	// Handle scoped packages
	if strings.HasPrefix(entry, "@") {
		// Find the second @ which separates name from version
		idx := strings.Index(entry[1:], "@")
		if idx > 0 {
			return entry[:idx+1]
		}
		// No version specified, return as-is
		return entry
	}

	// Regular package
	parts := strings.SplitN(entry, "@", 2)
	return parts[0]
}

// isBerryVersionRangeStart checks if a character indicates the start of a version range
// (used to distinguish Berry format from Yarn v1 npm aliases)
func isBerryVersionRangeStart(c byte) bool {
	return c == '^' || c == '~' || c == '>' || c == '<' || c == '=' || (c >= '0' && c <= '9')
}

// hasBerryStyleNpmPrefix checks if a declaration line has Berry-style @npm: prefix
// Berry format: "pkg@npm:^1.0.0:" where @npm: comes before the version range
// Yarn v1 aliases: "alias@npm:actual-pkg@version:" where @npm: is followed by a package name
func hasBerryStyleNpmPrefix(trimmed string) bool {
	npmIdx := strings.Index(trimmed, "@npm:")
	if npmIdx < 0 {
		return false
	}
	afterNpm := trimmed[npmIdx+5:] // After "@npm:"
	if len(afterNpm) == 0 {
		return false
	}
	return isBerryVersionRangeStart(afterNpm[0])
}

// isYarnBerryFormat detects if a yarn.lock file is in Yarn Berry (v2+) format.
// Berry format has a __metadata: section at the top and uses different syntax.
func isYarnBerryFormat(content string) bool {
	// Check for __metadata: header which is unique to Yarn Berry
	if strings.Contains(content, "__metadata:") {
		return true
	}

	// Check for Berry-style package declarations with @npm: prefix in declaration lines
	// e.g., "pkg@npm:^1.0.0:" instead of just "pkg@^1.0.0:"
	// Note: @npm: can appear in Yarn v1 for npm aliases (pkg@npm:other@1.0.0),
	// so we only check lines ending with ':' that have the Berry pattern
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		// Skip comments and empty lines
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		// Check declaration lines (ending with ':') for Berry-style @npm: prefix
		if strings.HasSuffix(trimmed, ":") && hasBerryStyleNpmPrefix(trimmed) {
			return true
		}
	}

	return false
}
