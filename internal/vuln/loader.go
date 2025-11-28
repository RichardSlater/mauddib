package vuln

import (
	"encoding/csv"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

const (
	// DataDogIOCURL is the primary IOC source from DataDog
	DataDogIOCURL = "https://raw.githubusercontent.com/DataDog/indicators-of-compromise/refs/heads/main/shai-hulud-2.0/consolidated_iocs.csv"
	// WizIOCURL is the secondary IOC source from Wiz (uses npm version specification format)
	WizIOCURL = "https://raw.githubusercontent.com/wiz-sec-public/wiz-research-iocs/main/reports/shai-hulud-2-packages.csv"
	// DefaultIOCURL is kept for backward compatibility
	DefaultIOCURL = DataDogIOCURL
)

// WarningFunc is called when a non-fatal warning occurs during parsing
type WarningFunc func(message string)

// defaultWarningFunc is used when no warning function is provided
var defaultWarningFunc WarningFunc = func(message string) {
	// Default: silent, warnings are ignored
}

// currentWarningFunc holds the active warning callback
var currentWarningFunc = defaultWarningFunc

// SetWarningFunc sets the function to call when warnings occur
// Returns the previous warning function
func SetWarningFunc(fn WarningFunc) WarningFunc {
	prev := currentWarningFunc
	if fn == nil {
		currentWarningFunc = defaultWarningFunc
	} else {
		currentWarningFunc = fn
	}
	return prev
}

// warn calls the current warning function
func warn(format string, args ...interface{}) {
	currentWarningFunc(fmt.Sprintf(format, args...))
}

// VulnEntry represents a vulnerable package entry
type VulnEntry struct {
	PackageName     string
	PackageVersion  string // Single version (after splitting comma-separated list)
	OriginalVersion string // Original version string from CSV (may be comma-separated)
}

// VulnDB holds the vulnerability database as a lookup map
type VulnDB struct {
	// Key: "package_name@version" for exact matches
	entries map[string]*VulnEntry
	// Index by package name for listing
	byName map[string][]*VulnEntry
	// Total entries count (before dedup)
	totalEntries int
}

// NewVulnDB creates a new vulnerability database
func NewVulnDB() *VulnDB {
	return &VulnDB{
		entries: make(map[string]*VulnEntry),
		byName:  make(map[string][]*VulnEntry),
	}
}

// LoadFromURL fetches and parses a CSV vulnerability database from a URL
func LoadFromURL(url string) (*VulnDB, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch vulnerability database: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch vulnerability database: HTTP %d", resp.StatusCode)
	}

	return parseCSV(resp.Body)
}

// LoadFromFile loads and parses a CSV vulnerability database from a local file
func LoadFromFile(path string) (*VulnDB, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open vulnerability file: %w", err)
	}
	defer f.Close()

	return parseCSV(f)
}

// ParseCSVForTest is a test helper that parses CSV from a reader
// Exported for use in tests
func ParseCSVForTest(r io.Reader) (*VulnDB, error) {
	return parseCSV(r)
}

// csvColumnIndices holds the detected column indices for CSV parsing
type csvColumnIndices struct {
	nameIdx      int
	versionIdx   int
	usedFallback bool
}

// detectColumnIndices finds the column indices for package name and version
func detectColumnIndices(header []string) csvColumnIndices {
	indices := csvColumnIndices{nameIdx: -1, versionIdx: -1}

	for i, col := range header {
		colLower := strings.ToLower(strings.TrimSpace(col))
		if colLower == "package_name" || colLower == "packagename" || colLower == "name" || colLower == "package" {
			indices.nameIdx = i
		}
		if colLower == "package_versions" || colLower == "package_version" || colLower == "packageversion" || colLower == "version" || colLower == "versions" {
			indices.versionIdx = i
		}
	}

	// Fall back to positional parsing if headers not recognized
	if indices.nameIdx == -1 {
		indices.nameIdx = 0
		indices.usedFallback = true
	}
	if indices.versionIdx == -1 {
		indices.versionIdx = 1
		indices.usedFallback = true
	}

	return indices
}

// readAllRecords reads all records from the CSV reader, skipping malformed lines
func readAllRecords(reader *csv.Reader) [][]string {
	var records [][]string
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue // Skip malformed lines
		}
		records = append(records, record)
	}
	return records
}

// warnFallbackParsing issues a warning when fallback parsing is used
func warnFallbackParsing(header []string, records [][]string, indices csvColumnIndices) {
	if !indices.usedFallback || len(records) == 0 {
		return
	}

	sampleCount := 3
	if len(records) < sampleCount {
		sampleCount = len(records)
	}

	var samples []string
	for i := 0; i < sampleCount; i++ {
		rec := records[i]
		if len(rec) > 1 {
			samples = append(samples, fmt.Sprintf("  %s @ %s", rec[indices.nameIdx], rec[indices.versionIdx]))
		}
	}

	warn("CSV headers not recognized (found: %v). Assuming column 1 = package name, column 2 = version. Sample data:\n%s",
		header, strings.Join(samples, "\n"))
}

// processRecord processes a single CSV record and adds entries to the database
func processRecord(db *VulnDB, record []string, indices csvColumnIndices) {
	if indices.nameIdx >= len(record) {
		return
	}

	packageName := strings.TrimSpace(record[indices.nameIdx])
	if packageName == "" {
		return
	}

	versionField := ""
	if indices.versionIdx >= 0 && indices.versionIdx < len(record) {
		versionField = strings.TrimSpace(record[indices.versionIdx])
	}

	if versionField == "" {
		return // Skip entries without version
	}

	versions := parseVersionList(versionField)
	for _, version := range versions {
		db.Add(&VulnEntry{
			PackageName:     packageName,
			PackageVersion:  version,
			OriginalVersion: versionField,
		})
	}
}

// parseCSV parses a CSV file looking for package_name and package_version columns
// Handles comma-separated version lists like "6.10.1, 6.8.2, 6.8.3"
// If column headers are not recognized, falls back to positional parsing (first=name, second=version)
func parseCSV(r io.Reader) (*VulnDB, error) {
	db := NewVulnDB()
	reader := csv.NewReader(r)

	header, err := reader.Read()
	if err != nil {
		return nil, fmt.Errorf("failed to read CSV header: %w", err)
	}

	if len(header) < 2 {
		return nil, fmt.Errorf("CSV must have at least 2 columns (package name and version)")
	}

	indices := detectColumnIndices(header)
	allRecords := readAllRecords(reader)
	warnFallbackParsing(header, allRecords, indices)

	for _, record := range allRecords {
		processRecord(db, record, indices)
	}

	return db, nil
}

// parseVersionList splits a comma-separated version string into individual versions
// e.g., "6.10.1, 6.8.2, 6.8.3" -> ["6.10.1", "6.8.2", "6.8.3"]
func parseVersionList(versionField string) []string {
	// Check if this looks like an npm version specification (contains "= ")
	if strings.Contains(versionField, "= ") || strings.HasPrefix(versionField, "=") {
		return parseNpmVersionSpec(versionField)
	}

	var versions []string

	// Split by comma
	parts := strings.Split(versionField, ",")
	for _, part := range parts {
		version := strings.TrimSpace(part)
		if version != "" {
			versions = append(versions, version)
		}
	}

	// If no valid versions found, return the original as-is
	if len(versions) == 0 && versionField != "" {
		versions = append(versions, versionField)
	}

	return versions
}

// parseNpmVersionSpec parses npm version specification format used by Wiz IOC list
// e.g., "= 1.0.0 || = 2.0.0" -> ["1.0.0", "2.0.0"]
// e.g., "= 1.0.0" -> ["1.0.0"]
// This handles the exact version match format: = X.Y.Z
func parseNpmVersionSpec(versionSpec string) []string {
	var versions []string

	// Split by "||" (the OR operator in npm semver)
	parts := strings.Split(versionSpec, "||")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		// Remove the leading "=" or "= " prefix
		if strings.HasPrefix(part, "=") {
			part = strings.TrimPrefix(part, "=")
			part = strings.TrimSpace(part)
		}

		if part != "" {
			versions = append(versions, part)
		}
	}

	return versions
}

// Add adds a vulnerability entry to the database
func (db *VulnDB) Add(entry *VulnEntry) {
	db.totalEntries++

	// Create key with name@version
	key := entry.PackageName + "@" + entry.PackageVersion

	// Only add if not already present (dedup)
	if _, exists := db.entries[key]; !exists {
		db.entries[key] = entry
		db.byName[entry.PackageName] = append(db.byName[entry.PackageName], entry)
	}
}

// Check checks if a package name and version are vulnerable
// Returns the matching VulnEntry if found, nil otherwise
// BOTH package name AND version must match for a positive result
func (db *VulnDB) Check(name, version string) *VulnEntry {
	if name == "" || version == "" {
		return nil
	}

	// Look for exact match of name@version
	key := name + "@" + version
	if entry, ok := db.entries[key]; ok {
		return entry
	}

	return nil
}

// GetVulnerableVersions returns all known vulnerable versions for a package name
func (db *VulnDB) GetVulnerableVersions(name string) []string {
	entries, ok := db.byName[name]
	if !ok {
		return nil
	}

	versions := make([]string, 0, len(entries))
	for _, entry := range entries {
		versions = append(versions, entry.PackageVersion)
	}
	return versions
}

// Size returns the number of unique package@version entries in the database
func (db *VulnDB) Size() int {
	return len(db.entries)
}

// UniquePackages returns the number of unique package names
func (db *VulnDB) UniquePackages() int {
	return len(db.byName)
}

// TotalEntries returns the total number of entries processed (before dedup)
func (db *VulnDB) TotalEntries() int {
	return db.totalEntries
}

// Merge adds all entries from another VulnDB into this one
// Duplicates (same package@version) are automatically deduplicated
func (db *VulnDB) Merge(other *VulnDB) {
	if other == nil {
		return
	}

	for _, entry := range other.entries {
		db.Add(entry)
	}
}

// LoadFromMultipleURLs fetches and merges CSV vulnerability databases from multiple URLs
// Errors from individual URLs are collected but don't stop the overall process
// Returns an error only if ALL sources fail to load
func LoadFromMultipleURLs(urls []string) (*VulnDB, error) {
	if len(urls) == 0 {
		return nil, fmt.Errorf("no URLs provided")
	}

	db := NewVulnDB()
	var errors []string
	successCount := 0

	for _, url := range urls {
		sourceDB, err := LoadFromURL(url)
		if err != nil {
			errors = append(errors, fmt.Sprintf("%s: %v", url, err))
			continue
		}
		db.Merge(sourceDB)
		successCount++
	}

	if successCount == 0 {
		return nil, fmt.Errorf("failed to load any IOC sources: %s", strings.Join(errors, "; "))
	}

	return db, nil
}

// DefaultIOCURLs returns the list of default IOC sources (DataDog and Wiz)
func DefaultIOCURLs() []string {
	return []string{DataDogIOCURL, WizIOCURL}
}
