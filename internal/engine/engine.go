package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/openhoo/hoolicy/internal/config"
	"github.com/openhoo/hoolicy/internal/packs"
	"github.com/openhoo/hoolicy/internal/repository"
	"github.com/openhoo/hoolicy/internal/safepath"
	"github.com/openhoo/hoolicy/sdk"
)

type Options struct {
	Now               time.Time
	BaseSHA           string
	MergeRequestTitle string
	ToolVersion       string
	GitContext        *sdk.GitContext
}

type Report struct {
	ReportVersion int            `json:"reportVersion"`
	Tool          Tool           `json:"tool"`
	Project       string         `json:"project"`
	GeneratedAt   time.Time      `json:"generatedAt"`
	ConfigDigest  string         `json:"configDigest"`
	Git           sdk.GitContext `json:"git"`
	FailOn        sdk.Severity   `json:"failOn"`
	Findings      []sdk.Finding  `json:"findings"`
	Summary       Summary        `json:"summary"`
}

type Tool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type Summary struct {
	Rules    int `json:"rules"`
	Errors   int `json:"errors"`
	Warnings int `json:"warnings"`
	Info     int `json:"info"`
	Waived   int `json:"waived"`
	Blocking int `json:"blocking"`
}

type Engine struct {
	registry *sdk.Registry
}

func New(registry *sdk.Registry) *Engine { return &Engine{registry: registry} }

func (e *Engine) Validate(project *config.Project) ([]sdk.Rule, error) {
	rules, err := packs.Resolve(project)
	if err != nil {
		return nil, err
	}
	for _, rule := range rules {
		kind, exists := e.registry.Kind(rule.Kind)
		if !exists {
			return nil, fmt.Errorf("rule %s uses unknown kind %s", rule.ID, rule.Kind)
		}
		if err := kind.Validate(rule); err != nil {
			return nil, err
		}
	}
	return rules, nil
}

func (e *Engine) Check(ctx context.Context, project *config.Project, options Options) (*Report, error) {
	rules, err := e.Validate(project)
	if err != nil {
		return nil, err
	}
	now := options.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	repo, err := repository.Open(project.Root, repository.Options{BaseSHA: options.BaseSHA, MergeRequestTitle: options.MergeRequestTitle, GitContext: options.GitContext})
	if err != nil {
		return nil, err
	}
	input := sdk.EvalContext{Repository: repo, Now: now, Parameters: project.Parameters}
	var findings []sdk.Finding
	for _, rule := range rules {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		kind, _ := e.registry.Kind(rule.Kind)
		result, evalErr := kind.Evaluate(ctx, input, rule)
		if evalErr != nil {
			return nil, fmt.Errorf("rule %s: %w", rule.ID, evalErr)
		}
		for index := range result {
			result[index].Finalize(rule)
			findings = append(findings, result[index])
		}
	}
	findings = applyWaivers(project, now, findings)
	sortFindings(findings)
	digest, err := projectDigest(project, rules)
	if err != nil {
		return nil, err
	}
	report := &Report{
		ReportVersion: 1, Tool: Tool{Name: "hoolicy", Version: options.ToolVersion},
		Project: project.Project, GeneratedAt: now, ConfigDigest: digest,
		Git: repo.Git(), FailOn: project.FailOn, Findings: findings,
	}
	report.Summary = summarize(findings, project.FailOn)
	report.Summary.Rules = len(rules)
	return report, nil
}

func summarize(findings []sdk.Finding, failOn sdk.Severity) Summary {
	var summary Summary
	for _, item := range findings {
		switch item.Severity {
		case sdk.SeverityError:
			summary.Errors++
		case sdk.SeverityWarning:
			summary.Warnings++
		case sdk.SeverityInfo:
			summary.Info++
		}
		if item.Waived {
			summary.Waived++
			continue
		}
		if item.Severity.Rank() >= failOn.Rank() {
			summary.Blocking++
		}
	}
	return summary
}

func applyWaivers(project *config.Project, now time.Time, findings []sdk.Finding) []sdk.Finding {
	_, path, pathErr := safepath.Existing(project.Root, project.Waivers)
	if errors.Is(pathErr, os.ErrNotExist) {
		return findings
	}
	if pathErr != nil {
		return append(findings, systemFinding("hoolicy.waivers", "Waiver path is unsafe: "+pathErr.Error(), project.Waivers, "path"))
	}
	waiverFile, err := config.LoadWaivers(path)
	if err != nil {
		return append(findings, systemFinding("hoolicy.waivers", "Waiver file is invalid: "+err.Error(), project.Waivers, "parse"))
	}
	seen := map[string]bool{}
	for _, waiver := range waiverFile.Waivers {
		if seen[waiver.ID] {
			findings = append(findings, systemFinding("hoolicy.waivers", "Duplicate waiver ID: "+waiver.ID, project.Waivers, waiver.ID))
			continue
		}
		seen[waiver.ID] = true
		if err := config.ValidateWaiver(waiver, now); err != nil {
			findings = append(findings, systemFinding("hoolicy.waivers", "Invalid waiver "+waiver.ID+": "+err.Error(), project.Waivers, waiver.ID))
			continue
		}
		used := false
		fingerprints := make(map[string]bool, len(waiver.Fingerprints))
		for _, fingerprint := range waiver.Fingerprints {
			fingerprints[fingerprint] = true
		}
		for index := range findings {
			item := &findings[index]
			if strings.HasPrefix(item.RuleID, "hoolicy.") || item.RuleID != waiver.Rule {
				continue
			}
			matched := fingerprints[item.Fingerprint]
			if !matched && item.Location.Path != "" && len(waiver.Paths) > 0 {
				matched, _ = repository.Matches(item.Location.Path, waiver.Paths)
			}
			if matched {
				item.Waived = true
				item.WaiverID = waiver.ID
				used = true
			}
		}
		if !used {
			findings = append(findings, systemFinding("hoolicy.waivers", "Stale waiver matches no current finding: "+waiver.ID, project.Waivers, waiver.ID))
		}
	}
	return findings
}

func systemFinding(ruleID, message, path, key string) sdk.Finding {
	rule := sdk.Rule{ID: ruleID, Title: "Hoolicy policy lifecycle", Remediation: "Correct or remove the invalid policy metadata.", Severity: sdk.SeverityError}
	result := sdk.Finding{RuleID: ruleID, Title: rule.Title, Message: message, Remediation: rule.Remediation, Severity: rule.Severity, Location: sdk.Location{Path: path, Line: 1, Column: 1}, Key: key}
	result.Finalize(rule)
	return result
}

func sortFindings(findings []sdk.Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		left, right := findings[i], findings[j]
		if left.Severity.Rank() != right.Severity.Rank() {
			return left.Severity.Rank() > right.Severity.Rank()
		}
		if left.Location.Path != right.Location.Path {
			return left.Location.Path < right.Location.Path
		}
		if left.Location.Line != right.Location.Line {
			return left.Location.Line < right.Location.Line
		}
		if left.RuleID != right.RuleID {
			return left.RuleID < right.RuleID
		}
		return left.Fingerprint < right.Fingerprint
	})
}

func projectDigest(project *config.Project, rules []sdk.Rule) (string, error) {
	hash := sha256.New()
	for _, input := range []struct{ label, path string }{
		{label: config.DefaultFilename, path: project.Path},
		{label: config.DefaultLockfile, path: filepath.Join(project.Root, config.DefaultLockfile)},
		{label: filepath.ToSlash(project.Waivers), path: filepath.Join(project.Root, filepath.FromSlash(project.Waivers))},
	} {
		data, err := os.ReadFile(input.path)
		if err == nil {
			hash.Write([]byte(input.label))
			hash.Write([]byte{0})
			hash.Write(data)
			hash.Write([]byte{0})
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
	}
	active, err := json.Marshal(rules)
	if err != nil {
		return "", fmt.Errorf("encode active policy digest: %w", err)
	}
	hash.Write(active)
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}
