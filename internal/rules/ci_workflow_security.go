package rules

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/openhoo/hoolicy/internal/document"
	"github.com/openhoo/hoolicy/sdk"
)

type CIWorkflowSecurity struct{}

type ciWorkflowSpec struct {
	Provider                string   `yaml:"provider,omitempty"`
	AllowedWritePermissions []string `yaml:"allowedWritePermissions,omitempty"`
	RequireJobTimeout       bool     `yaml:"requireJobTimeout,omitempty"`
}

var fullCommitRef = regexp.MustCompile(`^[0-9a-f]{40}$`)
var sha256Ref = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

func (CIWorkflowSecurity) Validate(rule sdk.Rule) error {
	if err := requireFiles(rule); err != nil {
		return err
	}
	var spec ciWorkflowSpec
	if err := decodeSpec(rule, &spec); err != nil {
		return err
	}
	if spec.Provider == "" {
		spec.Provider = "auto"
	}
	if spec.Provider != "auto" && spec.Provider != "github" && spec.Provider != "gitlab" {
		return fmt.Errorf("rule %s: provider must be auto, github, or gitlab", rule.ID)
	}
	for _, permission := range spec.AllowedWritePermissions {
		if strings.TrimSpace(permission) == "" {
			return fmt.Errorf("rule %s: allowed write permission must not be empty", rule.ID)
		}
	}
	return nil
}

func (CIWorkflowSecurity) Evaluate(_ context.Context, input sdk.EvalContext, rule sdk.Rule) ([]sdk.Finding, error) {
	var spec ciWorkflowSpec
	if err := decodeSpec(rule, &spec); err != nil {
		return nil, err
	}
	if spec.Provider == "" {
		spec.Provider = "auto"
	}
	files, err := input.Repository.Match(rule.Files, rule.Exclude)
	if err != nil {
		return nil, err
	}
	allowedWrites := map[string]bool{}
	for _, permission := range spec.AllowedWritePermissions {
		allowedWrites[permission] = true
	}
	var findings []sdk.Finding
	for _, file := range files {
		documents, hit, err := document.ParseCached(file, "yaml")
		if err != nil {
			return nil, err
		}
		if hit && input.Metrics != nil {
			input.Metrics.ParseCacheHits++
		}
		if len(documents) != 1 {
			return nil, fmt.Errorf("%s: CI workflow must contain exactly one YAML document", file.Path)
		}
		root, ok := documents[0].Data.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%s: CI workflow root must be an object", file.Path)
		}
		provider := spec.Provider
		if provider == "auto" {
			if strings.Contains(file.Path, ".github/workflows/") {
				provider = "github"
			} else {
				provider = "gitlab"
			}
		}
		if provider == "github" {
			findings = append(findings, inspectGitHubWorkflow(rule, file.Path, root, allowedWrites, spec.RequireJobTimeout)...)
		} else {
			findings = append(findings, inspectGitLabWorkflow(rule, file.Path, root, spec.RequireJobTimeout)...)
		}
	}
	return findings, nil
}

func inspectGitHubWorkflow(rule sdk.Rule, path string, root map[string]any, allowedWrites map[string]bool, requireTimeout bool) []sdk.Finding {
	var findings []sdk.Finding
	add := func(message, key string) { findings = append(findings, finding(rule, message, path, key, 1, 1)) }
	privilegedPullRequest := containsMapKey(root["on"], "pull_request_target") || root["on"] == "pull_request_target"
	if permissions, exists := root["permissions"]; !exists {
		add("Top-level token permissions are implicit; declare least-privilege permissions", "permissions:missing")
	} else {
		for _, problem := range excessivePermissions(permissions, allowedWrites) {
			add(problem, "permissions:"+problem)
		}
	}
	jobs, jobsOK := root["jobs"].(map[string]any)
	if !jobsOK || len(jobs) == 0 {
		add("Workflow jobs must be a non-empty object", "jobs:invalid")
		return findings
	}
	for jobName, raw := range jobs {
		job, ok := raw.(map[string]any)
		if !ok {
			add("Job "+jobName+" must be an object", "job:"+jobName+":invalid")
			continue
		}
		_, reusableWorkflow := job["uses"].(string)
		if requireTimeout && !reusableWorkflow {
			if _, exists := job["timeout-minutes"]; !exists {
				add("Job "+jobName+" has no timeout-minutes", "job:"+jobName+":timeout")
			}
		}
		if permissions, exists := job["permissions"]; exists {
			for _, problem := range excessivePermissions(permissions, allowedWrites) {
				add("Job "+jobName+": "+problem, "job:"+jobName+":permissions:"+problem)
			}
		}
		steps, stepsOK := job["steps"].([]any)
		if !stepsOK {
			if _, reusable := job["uses"].(string); !reusable {
				add("Job "+jobName+" needs steps or a reusable workflow", "job:"+jobName+":steps")
			}
			continue
		}
		for index, rawStep := range steps {
			step, ok := rawStep.(map[string]any)
			if !ok {
				add("Job "+jobName+" has a malformed step", fmt.Sprintf("job:%s:step:%d:invalid", jobName, index))
				continue
			}
			if uses, ok := step["uses"].(string); ok && !strings.HasPrefix(uses, "./") {
				_, ref, found := strings.Cut(uses, "@")
				if !found || !fullCommitRef.MatchString(ref) && !sha256Ref.MatchString(ref) {
					add("Action "+uses+" is not pinned to an immutable commit or digest", fmt.Sprintf("job:%s:step:%d:uses", jobName, index))
				}
				if privilegedPullRequest && strings.HasPrefix(uses, "actions/checkout@") && containsUntrustedPullRequestValue(step["with"]) {
					add("pull_request_target checks out untrusted pull-request code", fmt.Sprintf("job:%s:step:%d:privileged-checkout", jobName, index))
				}
			}
			if script, ok := step["run"].(string); ok && (strings.Contains(script, "${{ github.event.") || strings.Contains(script, "${{ github.head_ref")) {
				add("Run script interpolates untrusted GitHub event data directly", fmt.Sprintf("job:%s:step:%d:interpolation", jobName, index))
			}
		}
	}
	return findings
}

func excessivePermissions(value any, allowed map[string]bool) []string {
	if text, ok := value.(string); ok {
		if text == "write-all" {
			return []string{"write-all token permission is forbidden"}
		}
		if text != "read-all" {
			return []string{"token permissions value " + text + " is invalid"}
		}
		return nil
	}
	permissions, ok := value.(map[string]any)
	if !ok {
		return []string{"token permissions must be read-all, write-all, or an object"}
	}
	var problems []string
	for name, raw := range permissions {
		text, ok := raw.(string)
		if !ok || text != "read" && text != "write" && text != "none" {
			problems = append(problems, name+" token permission is invalid")
			continue
		}
		if text == "write" && !allowed[name] {
			problems = append(problems, name+" write permission is not approved")
		}
	}
	return problems
}

func inspectGitLabWorkflow(rule sdk.Rule, path string, root map[string]any, requireTimeout bool) []sdk.Finding {
	var findings []sdk.Finding
	add := func(message, key string) { findings = append(findings, finding(rule, message, path, key, 1, 1)) }
	for index, include := range asList(root["include"]) {
		switch current := include.(type) {
		case string:
			if strings.HasPrefix(current, "http://") || strings.HasPrefix(current, "https://") {
				add("Remote GitLab include is mutable and has no immutable project ref", fmt.Sprintf("include:%d", index))
			}
		case map[string]any:
			if _, remote := current["remote"]; remote {
				add("Remote GitLab include is mutable", fmt.Sprintf("include:%d", index))
				continue
			}
			if _, project := current["project"]; project {
				ref, _ := current["ref"].(string)
				if !fullCommitRef.MatchString(ref) {
					add("Project include is not pinned to a full commit SHA", fmt.Sprintf("include:%d", index))
				}
			}
		}
	}
	reserved := map[string]bool{"stages": true, "variables": true, "workflow": true, "default": true, "include": true, "image": true, "services": true, "before_script": true, "after_script": true, "cache": true}
	defaultConfiguration, _ := root["default"].(map[string]any)
	_, defaultTimeout := defaultConfiguration["timeout"]
	untrusted := []string{"$CI_MERGE_REQUEST_TITLE", "$CI_MERGE_REQUEST_DESCRIPTION", "$CI_MERGE_REQUEST_SOURCE_BRANCH_NAME"}
	for name, raw := range root {
		if reserved[name] || strings.HasPrefix(name, ".") {
			continue
		}
		job, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if requireTimeout && !defaultTimeout {
			if _, exists := job["timeout"]; !exists {
				add("Job "+name+" has no timeout", "job:"+name+":timeout")
			}
		}
		for _, script := range stringList(job["script"]) {
			for _, variable := range untrusted {
				if strings.Contains(script, variable) {
					add("Job "+name+" script consumes untrusted merge-request variable "+variable, "job:"+name+":interpolation:"+variable)
				}
			}
		}
	}
	return findings
}

func containsUntrustedPullRequestValue(value any) bool {
	switch current := value.(type) {
	case string:
		return strings.Contains(current, "github.event.pull_request.head") || strings.Contains(current, "github.head_ref")
	case map[string]any:
		for _, child := range current {
			if containsUntrustedPullRequestValue(child) {
				return true
			}
		}
	case []any:
		for _, child := range current {
			if containsUntrustedPullRequestValue(child) {
				return true
			}
		}
	}
	return false
}

func containsMapKey(value any, key string) bool {
	object, ok := value.(map[string]any)
	if !ok {
		return false
	}
	_, exists := object[key]
	return exists
}

func asList(value any) []any {
	if value == nil {
		return nil
	}
	if values, ok := value.([]any); ok {
		return values
	}
	return []any{value}
}

func stringList(value any) []string {
	var result []string
	for _, item := range asList(value) {
		if text, ok := item.(string); ok {
			result = append(result, text)
		}
	}
	return result
}
