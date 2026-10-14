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
			Explanation: starterExplanation(id),
			Exclude:     []string{".hoolicy/vendor/**", "**/node_modules/**", "node_modules/**", "vendor/**", "dist/**", "build/**"},
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

func starterExplanation(id string) *sdk.Explanation {
	switch id {
	case "repository.readme":
		return &sdk.Explanation{Expectation: "README.md exists at the repository root and is included in the repository snapshot.", Impact: "Contributors cannot discover how to set up, use, or operate this project.", Steps: []string{"Add a README with the project's actual setup and usage instructions.", "Verify that Git includes the file and rerun hoolicy check."}}
	case "repository.license":
		return &sdk.Explanation{Expectation: "A root LICENSE or LICENSE.* file declares the project's approved license.", Impact: "Users cannot determine their rights to use or distribute the project.", Steps: []string{"Confirm the project's license with its owner.", "Add the approved license text and rerun hoolicy check."}}
	case "repository.security-policy":
		return &sdk.Explanation{Expectation: "A root SECURITY.md documents the supported versions and private vulnerability reporting path.", Impact: "Reporters may disclose vulnerabilities publicly or contact an unmonitored channel.", Steps: []string{"Confirm the maintained reporting channel and support scope.", "Document them in SECURITY.md and rerun hoolicy check."}}
	case "repository.git-naming":
		return &sdk.Explanation{Expectation: "Feature branches use a prefix such as feat/ or fix/ with a lowercase hyphenated name; commit subjects use Conventional Commits, for example feat: add policy explanations.", Impact: "History and automated release classification become inconsistent.", Steps: []string{"Identify whether the finding refers to a branch name or a commit subject.", "Correct that name using the configured convention; coordinate any changes to shared history.", "In detached CI checkouts, provide the source branch with --branch or HOOLICY_BRANCH."}}
	case "supply-chain.approved-sources":
		return &sdk.Explanation{Expectation: "Artifact hosts match the configured registry and package-source allowlists; strict and container-service profiles also require container digests.", Impact: "An unreviewed or mutable artifact source can change the code installed or deployed.", Steps: []string{"Locate the source declaration reported by the finding.", "Use a reviewed artifact from an approved host; where required, pin the image to its sha256 digest.", "If a new host is necessary, have its owner review the policy allowlist and rerun the check."}}
	case "go.dependencies", "node.dependencies":
		return &sdk.Explanation{Expectation: "Dependencies use reviewed sources and all locks required by this profile are committed.", Impact: "A clean checkout can install different dependency code or depend on local-only files.", Steps: []string{"Review the exact dependency or lock reported in the finding.", "Generate and commit the appropriate lock with the project's approved package tool, or replace the unreviewed dependency source.", "Rerun hoolicy check from the same repository."}}
	case "service.runbook":
		return &sdk.Explanation{Expectation: "RUNBOOK.md or docs/runbook.md is present with operating and recovery guidance.", Impact: "An operator has no discoverable recovery procedure during an incident.", Steps: []string{"Document deployment, health checks, rollback, and recovery with the service owner.", "Commit the runbook and rerun hoolicy check."}}
	default:
		return nil
	}
}
