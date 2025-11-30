package scanner

import (
	"encoding/json"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
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
	LockfileVersion string                    `yaml:"lockfileVersion"`
	Packages        map[string]PnpmLockEntry  `yaml:"packages"`
	Dependencies    map[string]interface{}    `yaml:"dependencies"`    // Optional, for reference
	DevDependencies map[string]interface{}    `yaml:"devDependencies"` // Optional, for reference
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
//   /pkg/1.0.0 -> (pkg, 1.0.0)
//   /@scope/pkg@1.0.0 -> (@scope/pkg, 1.0.0)
//   /pkg@1.0.0 -> (pkg, 1.0.0)
//   /@scope/pkg/1.0.0 -> (@scope/pkg, 1.0.0)
func parsePnpmPackageKey(key string) (name, version string) {
	// Remove leading slash
	key = strings.TrimPrefix(key, "/")

	// Handle scoped packages
	if strings.HasPrefix(key, "@") {
		// Find the @ that separates name from version
		// Format: @scope/pkg@version or @scope/pkg/version
		parts := strings.SplitN(key, "@", 3) // Split into ["", "scope/pkg", "version"] or ["", "scope/pkg/version"]
		if len(parts) < 2 {
			return "", ""
		}

		scopedName := "@" + parts[1]

		// Check if version is after @ or /
		if len(parts) == 3 {
			// Format: @scope/pkg@version
			return scopedName, parts[2]
		}

		// Format: @scope/pkg/version - split on last /
		if idx := strings.LastIndex(scopedName, "/"); idx > 0 {
			return scopedName[:idx], scopedName[idx+1:]
		}

		return "", ""
	}

	// Regular package: pkg@version or pkg/version
	if strings.Contains(key, "@") {
		parts := strings.SplitN(key, "@", 2)
		if len(parts) == 2 {
			return parts[0], parts[1]
		}
	}

	// Format: pkg/version
	if idx := strings.LastIndex(key, "/"); idx > 0 {
		return key[:idx], key[idx+1:]
	}

	return "", ""
}

// ParseYarnLock parses a yarn.lock v1 file and returns the list of packages
func ParseYarnLock(content string, includeDev bool) ([]*Package, error) {
	var packages []*Package
	seen := make(map[string]bool)

	lines := strings.Split(content, "\n")
	var currentNames []string
	var currentVersion string
	inEntry := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Skip comments and empty lines
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		// Check if this is a package declaration line (starts with package name)
		// Format: "pkg@^1.0.0", "pkg@~2.0.0":
		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") && strings.HasSuffix(trimmed, ":") {
			// Save previous entry if exists
			if inEntry && currentVersion != "" && len(currentNames) > 0 {
				for _, name := range currentNames {
					pkgKey := name + "@" + currentVersion
					if !seen[pkgKey] {
						seen[pkgKey] = true
						packages = append(packages, &Package{
							Name:    name,
							Version: currentVersion,
							IsDev:   false, // yarn.lock v1 doesn't track dev vs prod
							Source:  "transitive",
						})
					}
				}
			}

			// Parse new package names (can be multiple)
			// Remove trailing colon
			namesStr := strings.TrimSuffix(trimmed, ":")
			// Split by comma for multiple ranges
			nameRanges := strings.Split(namesStr, ",")
			currentNames = []string{}
			for _, nr := range nameRanges {
				nr = strings.TrimSpace(nr)
				// Remove quotes
				nr = strings.Trim(nr, "\"'")
				// Extract package name (before @)
				name := extractYarnPackageName(nr)
				if name != "" {
					currentNames = append(currentNames, name)
				}
			}
			currentVersion = ""
			inEntry = true
			continue
		}

		// Parse version field
		if inEntry && strings.HasPrefix(trimmed, "version") {
			parts := strings.SplitN(trimmed, " ", 2)
			if len(parts) == 2 {
				version := strings.Trim(parts[1], "\"'")
				currentVersion = version
			}
		}
	}

	// Save last entry
	if inEntry && currentVersion != "" && len(currentNames) > 0 {
		for _, name := range currentNames {
			pkgKey := name + "@" + currentVersion
			if !seen[pkgKey] {
				seen[pkgKey] = true
				packages = append(packages, &Package{
					Name:    name,
					Version: currentVersion,
					IsDev:   false,
					Source:  "transitive",
				})
			}
		}
	}

	return packages, nil
}

// extractYarnPackageName extracts the package name from a yarn.lock entry
// Examples:
//   "pkg@^1.0.0" -> pkg
//   "@scope/pkg@^1.0.0" -> @scope/pkg
//   "pkg@npm:other@1.0.0" -> pkg
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
