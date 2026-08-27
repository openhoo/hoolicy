package rules

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/openhoo/hoolicy/sdk"
)

type GitNaming struct{}

type gitNamingSpec struct {
	BranchPattern            string   `yaml:"branchPattern,omitempty"`
	AllowedBranches          []string `yaml:"allowedBranches,omitempty"`
	CommitPattern            string   `yaml:"commitPattern,omitempty"`
	MergeRequestTitlePattern string   `yaml:"mergeRequestTitlePattern,omitempty"`
	MergeRequestTitleMaximum int      `yaml:"mergeRequestTitleMaximum,omitempty"`
	Message                  string   `yaml:"message"`
}

func (GitNaming) Validate(rule sdk.Rule) error {
	var spec gitNamingSpec
	if err := decodeSpec(rule, &spec); err != nil {
		return err
	}
	if spec.BranchPattern == "" && spec.CommitPattern == "" && spec.MergeRequestTitlePattern == "" && spec.MergeRequestTitleMaximum == 0 {
		return fmt.Errorf("rule %s: git.naming needs at least one pattern", rule.ID)
	}
	if spec.MergeRequestTitleMaximum < 0 {
		return fmt.Errorf("rule %s: mergeRequestTitleMaximum must not be negative", rule.ID)
	}
	if len(spec.AllowedBranches) > 0 && spec.BranchPattern == "" {
		return fmt.Errorf("rule %s: allowedBranches requires branchPattern", rule.ID)
	}
	for _, expression := range []string{spec.BranchPattern, spec.CommitPattern, spec.MergeRequestTitlePattern} {
		if expression == "" {
			continue
		}
		if _, err := regexp.Compile(expression); err != nil {
			return fmt.Errorf("rule %s: %w", rule.ID, err)
		}
	}
	return nil
}

func (GitNaming) Evaluate(_ context.Context, input sdk.EvalContext, rule sdk.Rule) ([]sdk.Finding, error) {
	var spec gitNamingSpec
	if err := decodeSpec(rule, &spec); err != nil {
		return nil, err
	}
	git := input.Repository.Git()
	message := spec.Message
	if message == "" {
		message = "Git naming policy did not pass"
	}
	var findings []sdk.Finding
	if spec.BranchPattern != "" && git.Branch != "" && !slices.Contains(spec.AllowedBranches, git.Branch) {
		if !regexp.MustCompile(spec.BranchPattern).MatchString(git.Branch) {
			findings = append(findings, finding(rule, fmt.Sprintf("%s: branch %q", message, git.Branch), "", "branch:"+git.Branch, 0, 0))
		}
	}
	if spec.CommitPattern != "" {
		expression := regexp.MustCompile(spec.CommitPattern)
		for _, commit := range git.CommitSubjects {
			if !expression.MatchString(commit.Subject) {
				findings = append(findings, finding(rule, fmt.Sprintf("%s: commit %.12s %q", message, commit.SHA, commit.Subject), "", "commit:"+commit.SHA, 0, 0))
			}
		}
	}
	if title := strings.TrimSpace(git.MergeRequestTitle); title != "" {
		withoutDraft := strings.TrimPrefix(title, "Draft: ")
		if spec.MergeRequestTitlePattern != "" && !regexp.MustCompile(spec.MergeRequestTitlePattern).MatchString(title) {
			findings = append(findings, finding(rule, fmt.Sprintf("%s: merge request title %q", message, title), "", "merge-request-title", 0, 0))
		} else if spec.MergeRequestTitleMaximum > 0 && len([]rune(withoutDraft)) > spec.MergeRequestTitleMaximum {
			findings = append(findings, finding(rule, fmt.Sprintf("%s: merge request title exceeds %d characters", message, spec.MergeRequestTitleMaximum), "", "merge-request-title-length", 0, 0))
		}
	}
	return findings, nil
}
