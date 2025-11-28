# Muaddib

[![CI](https://github.com/RichardSlater/muaddib/actions/workflows/ci.yml/badge.svg)](https://github.com/RichardSlater/muaddib/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/RichardSlater/muaddib)](https://goreportcard.com/report/github.com/RichardSlater/muaddib)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Version](https://img.shields.io/github/go-mod-go-version/RichardSlater/muaddib)](https://go.dev/)
[![Release](https://img.shields.io/github/v/release/RichardSlater/muaddib)](https://github.com/RichardSlater/muaddib/releases/latest)

Shai-Hallud NPM Worm scanner for GitHub repositories. Scans organization or user repositories for vulnerable npm packages by checking `package.json` and `package-lock.json` files against an IOC (Indicators of Compromise) database.

## Features

- 🔍 Scans all repositories in a GitHub organization or user account
- 📦 Parses both `package.json` and `package-lock.json` files
- 🌳 Enumerates all dependencies including transitive (nested) dependencies
- 🛡️ Checks against multiple vulnerability databases (DataDog + Wiz IOC lists by default)
- 🚨 Detects malicious migration repositories (`*-migration` with "Shai-Hulud Migration" description)
- 🌿 Detects malicious `shai-hulud` branches
- 🐛 Detects malicious GitHub Actions workflows (discussion.yaml pattern)
- 💉 Detects malicious npm lifecycle scripts (`node bundle.js` in postinstall, etc.)
- ⏱️ Conservative rate limiting to avoid GitHub API limits
- 🎨 Colored terminal output with emoji indicators
- 📊 Summary reports with affected repository listings

## Installation

```bash
# Clone the repository
git clone https://github.com/rslater/muaddib.git
cd muaddib

# Build the binary
go build -o muaddib ./cmd/muaddib/
```

## GitHub Personal Access Token (PAT) Setup

Muaddib requires a GitHub Personal Access Token to access the GitHub API. Follow these steps to create a token with **minimal required permissions**.

### Step 1: Create a Fine-Grained Personal Access Token

1. Go to GitHub → **Settings** → **Developer settings** → **Personal access tokens** → **Fine-grained tokens**

2. Click **"Generate new token"**

3. Configure the token:

   | Setting         | Value                                         |
   |-----------------|-----------------------------------------------|
   | **Token name**  | `muaddib-scanner` (or any descriptive name)   |
   | **Expiration**  | Choose based on your needs (recommend 7 days) |
   | **Description** | Optional: "NPM vulnerability scanner"         |

4. **Resource owner**: Select the organization or your personal account you want to scan

5. **Repository access**: Choose one of:

   - **"All repositories"** - To scan all repos in the org/account
   - **"Only select repositories"** - To limit scope to specific repos

6. **Permissions** (expand "Repository permissions"):

   | Permission   | Access Level | Why Needed                                           |
   |--------------|--------------|------------------------------------------------------|
   | **Contents** | `Read-only`  | To read `package.json` and `package-lock.json` files |
   | **Metadata** | `Read-only`  | To list repositories (automatically selected)        |

   ⚠️ **No other permissions are required.** Leave all others as "No access".

7. Click **"Generate token"**

8. **Copy the token immediately** - it won't be shown again!

### Step 2: Securely Store the Token

> [!IMPORTANT]
> Treat your GitHub token like a password. Keep it secret and secure. While it might be tempting to simply `export GITHUB_TOKEN=your_token_here` in your shell, this can expose the token in shell history or process listings. Instead, consider using a password manager to store and retrieve the token securely (Option B).

#### Option A: Using an env file

Create a `.env` file that is **not committed to version control**:

```bash
# Create the file with restricted permissions
touch ~/.muaddib.env
chmod 600 ~/.muaddib.env

# Add your token with the format export GITHUB_TOKEN=github_pat_xxxx
vi ~/.muaddib.env
```

your `.muaddib.env` file should contain:

```bash
export GITHUB_TOKEN=github_pat_your_generated_token_here
```

Source it when needed:

```bash
source ~/.muaddib.env
./muaddib --org mycompany
```

#### Option B: Using a Password Manager / Secret Store

For enhanced security, retrieve the token from a secret manager:

```bash
# Example with 1Password CLI
export GITHUB_TOKEN=$(op read "op://Private/GitHub PAT/token")

# Example with Bitwarden CLI
export GITHUB_TOKEN=$(bw get password "github-muaddib-token")

# Example with macOS Keychain
export GITHUB_TOKEN=$(security find-generic-password -a "$USER" -s "github-muaddib" -w)

# Example with pass (Unix password manager)
export GITHUB_TOKEN=$(pass show github/muaddib-token)
```

### Step 3: Verify Token Works

```bash
./muaddib --org your-org-name --verbose
```

You should see:

```text
✅ Loaded X IOC entries (Y unique packages)
🔗 Connected to GitHub API (rate limit: 1.0 req/sec)
📦 Fetching repositories for organization: your-org-name
```

### Security Best Practices

1. **Never commit tokens to version control**

   ```bash
   echo ".env" >> .gitignore
   echo "*.env" >> .gitignore
   ```

2. **Use fine-grained tokens** instead of classic tokens - they have narrower scope

3. **Set expiration dates** - rotate tokens regularly

4. **Use the minimum required permissions** - only `Contents: Read` is needed

5. **Revoke tokens when not in use** - delete them from [Settings → Tokens](https://github.com/settings/tokens)

6. **For CI/CD pipelines**, use:
   - GitHub Actions: Repository or organization secrets
   - GitLab CI: Protected CI/CD variables
   - Other CI: Dedicated secrets management

## Usage

### Basic Usage

```bash
# Scan an organization
./muaddib --org mycompany

# Scan a user's repositories
./muaddib --user johndoe

# Verbose output (shows progress)
./muaddib --org mycompany --verbose
```

### Advanced Options

```bash
# Use a custom vulnerability CSV (replaces default sources)
./muaddib --org mycompany --vuln-csv ./my-iocs.csv

# Slower rate limit (for large orgs or to be extra safe)
./muaddib --org mycompany --rate-limit 0.5

# Skip devDependencies
./muaddib --org mycompany --skip-dev

# Combine options
./muaddib --org mycompany --verbose --rate-limit 0.5 --skip-dev
```

### Flags Reference

| Flag           | Default                 | Description                               |
|----------------|-------------------------|-------------------------------------------|
| `--org`        | -                       | GitHub organization to scan               |
| `--user`       | -                       | GitHub user to scan                       |
| `--vuln-csv`   | DataDog + Wiz IOC lists | Path or URL to vulnerability CSV (custom) |
| `--rate-limit` | `1.0`                   | API requests per second                   |
| `--skip-dev`   | `false`                 | Skip devDependencies                      |
| `--verbose`    | `false`                 | Enable detailed progress output           |

## Vulnerability Database Format

The tool accepts CSV files in two formats:

### DataDog Format

```csv
package_name,package_versions,sources
malicious-package,1.0.0,datadog
another-bad-pkg,"2.3.4, 2.3.5",datadog
compromised-lib,1.2.3,datadog
```

- Version field uses comma-separated list: `"1.0.0, 1.0.1, 1.0.2"`
- Column names: `package_name`, `package_versions`

### Wiz Format (npm semver specification)

```csv
Package,Version
malicious-package,= 1.0.0
another-bad-pkg,= 2.3.4 || = 2.3.5
compromised-lib,= 1.2.3
```

- Version field uses npm semver exact match syntax: `= X.Y.Z || = A.B.C`
- Column names: `Package`, `Version`

### Flexible Column Detection

The parser automatically detects column names using case-insensitive matching:

- **Package name column**: `package_name`, `packagename`, `name`, `package`, or `Package`
- **Version column**: `package_versions`, `package_version`, `packageversion`, `version`, `versions`, or `Version`

If column headers are not recognized, the parser falls back to positional parsing:

- **Column 1**: Package name
- **Column 2**: Version

When fallback parsing is used, a warning is displayed with sample data to help verify correctness.

### Default Data Sources

By default, Muaddib loads **both** IOC lists simultaneously:

1. **[DataDog IOC list](https://raw.githubusercontent.com/DataDog/indicators-of-compromise/refs/heads/main/shai-hulud-2.0/consolidated_iocs.csv)** - Primary source
2. **[Wiz IOC list](https://raw.githubusercontent.com/wiz-sec-public/wiz-research-iocs/main/reports/shai-hulud-2-packages.csv)** - Secondary source

The databases are merged and deduplicated automatically. This provides the most comprehensive coverage of known malicious packages.

## Output Example

```text
  __  __                 _  _     _  _  _
 |  \/  | _  _   __ _  __| |( ) __| |(_)| |__
 | |\/| || || | / _` |/ _` ||/ / _` || || '_ \
 | |  | || _,_|| (_| || (_| |  | (_| || || |_) |
 |_|  |_| \__,_|\__,_| \__,_|   \__,_||_||_.__/

   Shai-Hulud NPM Worm Scanner for GitHub

────────────────────────────────────────────────────────────
📥 Loading vulnerability database...
   Using default sources: DataDog + Wiz IOC lists
✅ Loaded 2180 IOC entries (795 unique packages, 1091 vulnerable versions)
🔗 Connected to GitHub API (rate limit: 1.0 req/sec)
📦 Fetching repositories for organization: example-org
✅ Found 25 repositories

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📁 Repository: example-org/vulnerable-app
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📦 Scanned 2 files, found 847 unique packages
🔴 Found 3 issue(s):

  💉 Malicious Script Detected:
     🔴 package.json
        Script: postinstall → node bundle.js
        Pattern: node bundle.js

  📄 package-lock.json:
     🔴 malicious-pkg@1.2.3 [transitive]
     🔴 bad-dependency@4.5.6 (dev) [transitive]

══════════════════════════════════════════════════════════════
                        SCAN SUMMARY
══════════════════════════════════════════════════════════════

📊 Repositories scanned:     25
📦 Total packages checked:   12847
🔍 IOC database entries:     156

🔴 Vulnerable packages found: 2
💉 Malicious scripts found:   1
⚠️  Affected repositories:    1

Affected repositories:
  🔴 example-org/vulnerable-app (2 vulnerable, 1 malicious script)

══════════════════════════════════════════════════════════════
```

## References

The following references were used in building this tool, all credit for detecting instances of Shai-Haluld infection should go to the companies and authors below:

- [GitLab discovers widespread npm supply chain attack](https://about.gitlab.com/blog/gitlab-discovers-widespread-npm-supply-chain-attack/) by Daniel Abeles and Michael Henriksen (GitLab),
- [The Shai-Hulud 2.0 npm worm: analysis, and what you need to know](https://securitylabs.datadoghq.com/articles/shai-hulud-2.0-npm-worm/) by Christophe Tafani-Dereeper and Sebastian Obregoso (DataDog),
- [Shai-Hulud 2.0: How Cortex Detects and Blocks the Resurgent npm Worm](https://www.paloaltonetworks.com/blog/cloud-security/shai-hulud-2-0-npm-worm-detection-blocking/) by Cameron Hyde and Yitzy Tannenbaum (Palo Alto Networks)
- [Shai-Hulud 2.0 Supply Chain Attack: 25K+ Repos Exposing Secrets](https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack) by Hila Ramati, Merav Bar, Gal Benmocha, Gili Tikochinski (wiz.io)
- [Widespread Supply Chain Compromise Impacting npm Ecosystem](https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem) by CISA
- [Post-mortem of Shai-Hulud attack on November 24th, 2025](https://posthog.com/blog/nov-24-shai-hulud-attack-post-mortem) by Oliver Browne (PostHog)
- [Shai-hulud npm attack: What you need to know](https://www.reversinglabs.com/blog/shai-hulud-worm-npm) by Karlo Zanki (Reversing Labs)
- [Shai Hulud 2.0: The NPM Supply Chain Attack Returns as an Aggressive Self-Propagating Worm](https://www.upwind.io/feed/shai-hulud-2-npm-supply-chain-worm-attack) by Koby Turjeman

## License

MIT
