# Technical Analysis: Lockfile Format Parsing

## Detailed Format Comparison

| Feature | pnpm-lock.yaml | yarn.lock v1 | yarn.lock v2+ | bun.lock | npm-shrinkwrap.json |
|---------|---------------|--------------|---------------|----------|---------------------|
| **Format** | YAML | Custom text | YAML-like | YAML-like | JSON |
| **Std Parser** | ✅ Yes | ❌ No | ⚠️ Partial | ⚠️ Partial | ✅ Yes |
| **Scoped pkgs** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Transitive** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Version in key** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Parse complexity** | 1/10 | 4/10 | 6/10 | 6/10 | 0/10 |
| **Lines of code** | ~50 | ~100 | ~150 | ~150 | 0 (reuse) |

---

## Scoped Package Handling

All formats support scoped packages, but they appear differently:

### pnpm-lock.yaml
```yaml
packages:
  '@babel/core@7.23.0':
    # Package name: @babel/core
    # Version: 7.23.0
```

**Parsing**:
```go
// Split on '@', handle leading '@'
if strings.HasPrefix(key, "@") {
    // @scope/name@version -> ["", "scope/name", "version"]
    parts := strings.Split(key, "@")
    name = "@" + parts[1]
    version = parts[2]
}
```

### yarn.lock v1
```
"@babel/core@^7.0.0":
  version "7.23.0"
```

**Parsing**:
```go
// Split on last '@' before ':'
colonIdx := strings.Index(line, ":")
pkgRange := line[:colonIdx]
lastAt := strings.LastIndex(pkgRange, "@")
name = pkgRange[:lastAt] // "@babel/core"
```

### yarn.lock v2+
```yaml
"@babel/core@npm:^7.0.0":
  version: 7.23.0
```

**Parsing**:
```go
// Remove quotes, split on '@npm:'
cleaned := strings.Trim(key, `"`)
parts := strings.Split(cleaned, "@npm:")
name = parts[0] // "@babel/core"
```

---

## Edge Cases to Handle

### 1. Multi-range in Yarn v1

```
lodash@^4.17.0, lodash@^4.17.21, lodash@~4.17.15:
  version "4.17.21"
```

**Solution**: Split on comma, process first entry only (or all, but deduplicate)

### 2. Peer dependencies (pnpm)

```yaml
packages:
  'typescript@5.3.3':
    resolution: {integrity: sha512-...}
    engines: {node: '>=14.17'}
    hasBin: true
```

**No dependencies field** = Still valid, might be a top-level or peer dep

### 3. Workspace protocols (Yarn v2+)

```yaml
"my-package@workspace:*":
  version: 0.0.0-use.local
  resolution: "my-package@workspace:packages/my-package"
```

**Solution**: Skip packages with `@workspace:` protocol (not from registry)

### 4. Git/tarball dependencies

```yaml
packages:
  'some-pkg@github.com/user/repo#commit':
    resolution: {tarball: https://...}
```

**Solution**: Skip non-semver versions for vulnerability scanning

### 5. Optional dependencies

```yaml
dependencies:
  fsevents:
    specifier: ^2.3.2
    version: 2.3.3
```

**pnpm**: Included in packages section
**Action**: Scan them (they're still installed)

---

## Performance Considerations

### File Sizes

Typical lockfile sizes for a medium project (100 direct deps, 500 transitive):

- `package-lock.json`: 300-500 KB
- `pnpm-lock.yaml`: 100-200 KB (more compact)
- `yarn.lock` v1: 200-400 KB
- `yarn.lock` v2+: 250-450 KB
- `bun.lock`: 150-300 KB

### Parsing Speed Estimates

For 500 packages:

1. **pnpm-lock.yaml**: ~5ms (YAML parser is fast)
2. **npm-shrinkwrap.json**: ~3ms (JSON parser, already implemented)
3. **yarn.lock v1**: ~10ms (line-by-line, regex)
4. **yarn.lock v2+**: ~15ms (YAML + custom parsing)

**Conclusion**: All formats parse in <20ms, not a bottleneck

---

## Memory Usage

### YAML Parser (pnpm/yarn v2+)

```go
import "gopkg.in/yaml.v3"

var data map[string]interface{}
yaml.Unmarshal(content, &data)
// Memory: ~2x file size (temporary structure)
```

**For 200KB file**: ~400KB memory (acceptable)

### Custom Parser (yarn v1)

```go
lines := strings.Split(content, "\n")
// Memory: 1x file size (string array)
// Process line-by-line, discard non-essential data
```

**For 300KB file**: ~300KB memory (acceptable)

---

## Error Handling

### Common Errors

1. **Malformed YAML**: Partial file download, corruption
2. **Unknown version**: Future lockfile versions
3. **Missing fields**: Truncated files
4. **Invalid package names**: Malicious repos

### Recommended Error Strategy

```go
func ParseLockfile(data []byte, format string) ([]Package, error) {
    packages, err := parseByFormat(data, format)
    if err != nil {
        return nil, fmt.Errorf("failed to parse %s: %w", format, err)
    }

    // Validation
    if len(packages) == 0 {
        return nil, fmt.Errorf("no packages found in %s", format)
    }

    // Filter invalid entries
    valid := make([]Package, 0, len(packages))
    for _, pkg := range packages {
        if isValidPackage(pkg) {
            valid = append(valid, pkg)
        }
    }

    return valid, nil
}

func isValidPackage(pkg Package) bool {
    // Skip workspace protocols
    if strings.Contains(pkg.Name, "@workspace:") {
        return false
    }

    // Skip git/tarball
    if strings.Contains(pkg.Version, "github.com") ||
       strings.Contains(pkg.Version, "http") {
        return false
    }

    // Must have valid semver
    if !semverRegex.MatchString(pkg.Version) {
        return false
    }

    return true
}
```

---

## Integration with Existing Code

### Current Architecture (Muaddib)

```
github/contents.go
  ↓ FindPackageFiles()
  → Returns: package.json, package-lock.json

scanner/parser.go
  ↓ ParsePackageJSON(), ParsePackageLock()
  → Returns: []Package

scanner/matcher.go
  ↓ CheckVulnerabilities()
  → Matches against VulnDB
```

### Proposed Extension

```
github/contents.go
  ↓ FindPackageFiles()
  → Returns: package.json, package-lock.json, pnpm-lock.yaml, yarn.lock

scanner/parser.go
  ↓ New functions:
  - ParsePnpmLock()
  - ParseYarnLockV1()
  - ParseYarnLockV2()
  - ParseBunLock()
  - DetectLockfileFormat()  ← Auto-detect

  ↓ Returns: []Package (uniform structure)

scanner/matcher.go
  ↓ CheckVulnerabilities() ← No changes needed!
  → Works with any []Package
```

**Key insight**: Matcher is format-agnostic, only parser needs changes

---

## Auto-Detection Strategy

```go
func DetectLockfileFormat(content []byte) string {
    str := string(content)

    // Check first 500 bytes for signatures
    header := str
    if len(str) > 500 {
        header = str[:500]
    }

    // pnpm
    if strings.Contains(header, "lockfileVersion:") {
        return "pnpm-lock.yaml"
    }

    // Yarn v1
    if strings.Contains(header, "# yarn lockfile v1") {
        return "yarn.lock.v1"
    }

    // Yarn v2+
    if strings.Contains(header, "__metadata:") {
        return "yarn.lock.v2"
    }

    // Bun
    if strings.Contains(header, "# bun lockfile") ||
       (strings.Contains(header, "__metadata:") &&
        strings.Contains(str, "@npm:")) {
        return "bun.lock"
    }

    // npm/shrinkwrap (JSON)
    if strings.HasPrefix(strings.TrimSpace(header), "{") {
        // Try to parse as JSON
        var data map[string]interface{}
        if json.Unmarshal(content, &data) == nil {
            if _, ok := data["lockfileVersion"]; ok {
                return "package-lock.json"
            }
        }
    }

    return "unknown"
}
```

---

## Test Data Generation

### Create Real Test Files

```bash
# In a temp directory
npm init -y
npm install lodash express

# Generates package-lock.json

pnpm install
# Generates pnpm-lock.yaml

yarn install
# Generates yarn.lock (v1 or v2+ depending on version)

bun install
# Generates bun.lock
```

### Minimal Test Files

**pnpm-lock.yaml** (minimal):
```yaml
lockfileVersion: '9.0'
packages:
  'test-pkg@1.0.0':
    resolution: {integrity: sha512-abc}
  '@scope/pkg@2.0.0':
    resolution: {integrity: sha512-def}
```

**yarn.lock v1** (minimal):
```
# yarn lockfile v1

test-pkg@^1.0.0:
  version "1.0.0"
  resolved "https://registry.yarnpkg.com/test-pkg-1.0.0.tgz"

"@scope/pkg@^2.0.0":
  version "2.0.0"
  resolved "https://registry.yarnpkg.com/@scope/pkg-2.0.0.tgz"
```

---

## Dependencies to Add

### For YAML Parsing

```bash
go get gopkg.in/yaml.v3
```

Add to `go.mod`:
```go
require (
    gopkg.in/yaml.v3 v3.0.1
)
```

**No other dependencies needed** - custom parsers can use stdlib only

---

## Compatibility Matrix

| Lockfile Format | Go Version | Dependencies | OS Support |
|----------------|------------|--------------|------------|
| pnpm-lock.yaml | 1.18+ | yaml.v3 | All |
| yarn.lock v1 | 1.18+ | stdlib only | All |
| yarn.lock v2+ | 1.18+ | yaml.v3 | All |
| bun.lock | 1.18+ | yaml.v3 | All |
| shrinkwrap | 1.18+ | stdlib only | All |

**Minimum Go version**: 1.18 (already required by Muaddib)

---

## Benchmarking Plan

### Test Suite

```go
func BenchmarkParsePnpm(b *testing.B) {
    data := loadTestFile("testdata/pnpm-lock.yaml")
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        ParsePnpmLock(data)
    }
}

func BenchmarkParseYarnV1(b *testing.B) {
    data := loadTestFile("testdata/yarn-v1.lock")
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        ParseYarnLockV1(data)
    }
}
```

**Run**:
```bash
go test -bench=. -benchmem ./internal/scanner/
```

**Expected results**:
- pnpm: 5ms/op, 400KB alloc
- yarn v1: 10ms/op, 300KB alloc
- All well within acceptable limits

---

## Rollout Strategy

### Phase 1: Foundation (Week 1)
- Add YAML dependency
- Implement pnpm-lock.yaml parser
- Add tests with real pnpm lockfiles
- Update contents.go to detect pnpm-lock.yaml

### Phase 2: Yarn Classic (Week 2)
- Implement yarn.lock v1 parser
- Handle multi-range entries
- Test with real yarn.lock files
- Update contents.go to detect yarn.lock

### Phase 3: Testing & Polish (Week 3)
- Add format auto-detection
- Handle edge cases (workspace, git deps)
- Performance benchmarks
- Documentation updates

### Phase 4: Advanced Formats (Future)
- Yarn v2+ Berry support
- Bun.lock support
- Based on user feedback
