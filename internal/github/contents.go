package github

import (
	"context"
	"encoding/base64"
	"fmt"
	"path"
	"strings"

	"github.com/google/go-github/v67/github"
)

// PackageFile represents a package manifest file found in a repository
type PackageFile struct {
	Path     string
	Content  string
	RepoName string
}

// WorkflowFile represents a GitHub Actions workflow file found in a repository
type WorkflowFile struct {
	Path     string
	Content  string
	RepoName string
}

// isPackageFile checks if a filename is a package manifest file
func isPackageFile(filename string) bool {
	return filename == "package.json" || filename == "package-lock.json"
}

// findPackageFilePaths extracts package file paths from a git tree
func findPackageFilePaths(tree *github.Tree) []string {
	var paths []string
	for _, entry := range tree.Entries {
		if entry.Type == nil || *entry.Type != "blob" || entry.Path == nil {
			continue
		}
		if isPackageFile(path.Base(*entry.Path)) {
			paths = append(paths, *entry.Path)
		}
	}
	return paths
}

// FindPackageFiles finds all package.json and package-lock.json files in a repository
func (c *Client) FindPackageFiles(ctx context.Context, repo *Repository) ([]*PackageFile, error) {
	if err := c.wait(ctx); err != nil {
		return nil, fmt.Errorf("rate limit wait: %w", err)
	}

	c.progress("🔍 Scanning %s for package files...", repo.FullName)

	tree, resp, err := c.client.Git.GetTree(ctx, repo.Owner, repo.Name, repo.DefaultBranch, true)
	if err != nil {
		if resp != nil && (resp.StatusCode == 409 || resp.StatusCode == 404) {
			c.progress("⚠️  Skipping %s (empty or no default branch)", repo.FullName)
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get tree for %s: %w", repo.FullName, err)
	}
	c.handleRateLimit(resp)

	packageFilePaths := findPackageFilePaths(tree)
	if len(packageFilePaths) == 0 {
		c.progress("📭 No package files found in %s", repo.FullName)
		return nil, nil
	}

	c.progress("📦 Found %d package file(s) in %s", len(packageFilePaths), repo.FullName)

	return c.fetchPackageFileContents(ctx, repo, packageFilePaths)
}

// fetchPackageFileContents fetches content for multiple package files
func (c *Client) fetchPackageFileContents(ctx context.Context, repo *Repository, paths []string) ([]*PackageFile, error) {
	var files []*PackageFile
	for _, filePath := range paths {
		if err := c.wait(ctx); err != nil {
			return nil, fmt.Errorf("rate limit wait: %w", err)
		}

		content, err := c.getFileContent(ctx, repo, filePath)
		if err != nil {
			c.progress("⚠️  Failed to fetch %s/%s: %v", repo.FullName, filePath, err)
			continue
		}

		files = append(files, &PackageFile{
			Path:     filePath,
			Content:  content,
			RepoName: repo.FullName,
		})
	}
	return files, nil
}

// FindMaliciousWorkflows finds the discussion.yaml workflow file if it exists
func (c *Client) FindMaliciousWorkflows(ctx context.Context, repo *Repository) ([]*WorkflowFile, error) {
	if err := c.wait(ctx); err != nil {
		return nil, fmt.Errorf("rate limit wait: %w", err)
	}

	// Get the tree recursively
	tree, resp, err := c.client.Git.GetTree(ctx, repo.Owner, repo.Name, repo.DefaultBranch, true)
	if err != nil {
		// Check if it's a 409 conflict (empty repo) or 404 (no default branch)
		if resp != nil && (resp.StatusCode == 409 || resp.StatusCode == 404) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get tree for %s: %w", repo.FullName, err)
	}
	c.handleRateLimit(resp)

	// Look for .github/workflows/discussion.yaml
	const targetPath = ".github/workflows/discussion.yaml"
	var found bool
	for _, entry := range tree.Entries {
		if entry.Type == nil || *entry.Type != "blob" {
			continue
		}
		if entry.Path == nil {
			continue
		}
		if *entry.Path == targetPath {
			found = true
			break
		}
	}

	if !found {
		return nil, nil
	}

	// Fetch content
	if err := c.wait(ctx); err != nil {
		return nil, fmt.Errorf("rate limit wait: %w", err)
	}

	content, err := c.getFileContent(ctx, repo, targetPath)
	if err != nil {
		c.progress("⚠️  Failed to fetch %s/%s: %v", repo.FullName, targetPath, err)
		return nil, nil
	}

	return []*WorkflowFile{
		{
			Path:     targetPath,
			Content:  content,
			RepoName: repo.FullName,
		},
	}, nil
}

// getFileContent fetches the content of a file from the repository
func (c *Client) getFileContent(ctx context.Context, repo *Repository, filePath string) (string, error) {
	fileContent, _, resp, err := c.client.Repositories.GetContents(ctx, repo.Owner, repo.Name, filePath, &github.RepositoryContentGetOptions{
		Ref: repo.DefaultBranch,
	})
	if err != nil {
		return "", fmt.Errorf("failed to get content: %w", err)
	}
	c.handleRateLimit(resp)

	if fileContent == nil {
		return "", fmt.Errorf("file content is nil")
	}

	// Handle different encodings
	if fileContent.Encoding != nil && *fileContent.Encoding == "base64" {
		if fileContent.Content == nil {
			return "", fmt.Errorf("content is nil")
		}
		decoded, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(*fileContent.Content, "\n", ""))
		if err != nil {
			return "", fmt.Errorf("failed to decode base64: %w", err)
		}
		return string(decoded), nil
	}

	// Try to get content directly
	content, err := fileContent.GetContent()
	if err != nil {
		return "", fmt.Errorf("failed to get content: %w", err)
	}

	return content, nil
}
