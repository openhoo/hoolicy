package cli

import "github.com/openhoo/hoolicy/sdk"

// Profiles embed only local rules: initialization and ordinary checks never
// acquire a policy pack or run a language package manager.
var starterProfiles = []struct{ name, description string }{
	{"empty", "No rules; build a policy from scratch"},
	{"standard", "Repository documentation, Git naming, and approved artifact sources"},
	{"strict", "Standard checks plus immutable container image references"},
	{"go-library", "Standard checks plus a Go module, dependency governance, and release notes"},
	{"go-service", "Standard checks plus a Go module, dependency locks, and an operating runbook"},
	{"node-library", "Standard checks plus npm metadata, dependency locks, and release notes"},
	{"node-service", "Standard checks plus npm metadata, dependency locks, and an operating runbook"},
	{"container-service", "Strict checks plus a container build definition, build context exclusions, and an operating runbook"},
}

func stackStarterRules(profile string) []sdk.Rule {
	var result []sdk.Rule
	add := func(id, title, description, rationale, remediation, kind string, files []string, spec map[string]any) {
		result = append(result, sdk.Rule{
			ID: id, Title: title, Description: description, Rationale: rationale,
			Remediation: remediation, Severity: sdk.SeverityError, Kind: kind, Files: files, Spec: spec,
			Exclude: []string{".hoolicy/vendor/**", "**/node_modules/**", "node_modules/**", "vendor/**", "dist/**", "build/**"},
		})
	}
	require := func(id, title, rationale, remediation string, files ...string) {
		add(id, title, "Requires at least one matching repository file.", rationale, remediation, "files", files,
			map[string]any{"mode": "require", "message": title})
	}
	switch profile {
	case "go-library", "go-service":
		require("go.module", "Go module manifest is required", "The module manifest defines the public module path and build inputs.", "Add a reviewed root go.mod for this module.", "go.mod")
		add("go.dependencies", "Go dependencies have reviewed sources", "Checks Go replacements and, for service profiles, go.sum presence.", "Unreviewed local replacements can make a repository build depend on a developer's machine.", "Remove local replacements or allowlist reviewed module names; services also commit go.sum.", "dependency.governance", []string{"**/go.mod"}, map[string]any{"requireLocks": profile == "go-service", "message": "Go dependency governance failed"})
	case "node-library", "node-service":
		require("node.manifest", "Node package manifest is required", "The package manifest declares reproducible package inputs.", "Add a reviewed root package.json.", "package.json")
		add("node.dependencies", "Node dependencies have locks and reviewed sources", "Checks package manager locks and mutable or local dependency sources.", "Committed locks and reviewed source boundaries prevent installation drift.", "Commit the lock for the declared package manager and replace mutable or unreviewed local sources.", "dependency.governance", []string{"**/package.json"}, map[string]any{"requireLocks": true, "message": "Node dependency governance failed"})
		add("node.metadata", "Node packages declare identity and license", "Checks nonempty package name, version, and license fields.", "Package consumers need an explicit identity and license declaration.", "Set reviewed nonempty name, version, and license fields in each package manifest.", "structured.cel", []string{"**/package.json"}, map[string]any{"format": "json", "expression": `documents.all(d, ['name', 'version', 'license'].all(k, k in d.data && type(d.data[k]) == string && size(d.data[k]) > 0))`, "message": "Node package identity or license declaration is missing"})
	case "container-service":
		require("container.build-definition", "Container build definition is required", "A checked-in build definition makes container inputs reviewable.", "Add a root Dockerfile or Containerfile.", "Dockerfile", "Containerfile")
		require("container.context-exclusions", "Container build context exclusions are required", "Explicit build context exclusions help keep local credentials and generated artifacts out of image inputs.", "Add a reviewed .dockerignore covering project-specific sensitive and generated files.", ".dockerignore")
	}
	switch profile {
	case "go-library", "node-library":
		require("library.release-notes", "Library release notes are required", "Consumers need a discoverable record of compatibility and migration changes.", "Document released changes in CHANGELOG.md or docs/changelog.md.", "CHANGELOG.md", "docs/changelog.md")
	case "go-service", "node-service", "container-service":
		require("service.runbook", "Service operating runbook is required", "Operators need discoverable recovery and deployment instructions.", "Add a reviewed RUNBOOK.md or docs/runbook.md covering operation and recovery.", "RUNBOOK.md", "docs/runbook.md")
	}
	return result
}
