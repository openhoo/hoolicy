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
	Branch            string
	ToolVersion       string
	GitContext        *sdk.GitContext
}

type Report struct {
	ReportVersion int               `json:"reportVersion"`
	Tool          Tool              `json:"tool"`
	Project       string            `json:"project"`
	GeneratedAt   time.Time         `json:"generatedAt"`
	ConfigDigest  string            `json:"configDigest"`
	PolicyDigest  string            `json:"policyDigest"`
	Git           sdk.GitContext    `json:"git"`
	FailOn        sdk.Severity      `json:"failOn"`
	Findings      []sdk.Finding     `json:"findings"`
	Waivers       []config.Waiver   `json:"waivers"`
	Changes       []Change          `json:"changes,omitempty"`
	Baseline      *BaselineStatus   `json:"baseline,omitempty"`
	Comparison    *Comparison       `json:"comparison,omitempty"`
	Summary       Summary           `json:"summary"`
	Metrics       EvaluationMetrics `json:"metrics"`
}

type EvaluationMetrics struct {
	Files                int          `json:"files"`
	Bytes                int64        `json:"bytes"`
	DurationMilliseconds int64        `json:"durationMilliseconds"`
	InputCacheHits       int          `json:"inputCacheHits"`
	ParseCacheHits       int          `json:"parseCacheHits"`
	Rules                []RuleMetric `json:"rules"`
}

type RuleMetric struct {
	RuleID               string `json:"ruleId"`
	Workspace            string `json:"workspace,omitempty"`
	Inputs               int    `json:"inputs"`
	Findings             int    `json:"findings"`
	DurationMilliseconds int64  `json:"durationMilliseconds"`
	InputCacheHits       int    `json:"inputCacheHits"`
	ParseCacheHits       int    `json:"parseCacheHits"`
	CELCost              uint64 `json:"celCost,omitempty"`
}

type Change struct {
	State         string       `json:"state"`
	Source        string       `json:"source"`
	Fingerprint   string       `json:"fingerprint"`
	RuleID        string       `json:"ruleId"`
	Severity      sdk.Severity `json:"severity"`
	PolicyDigest  string       `json:"policyDigest"`
	FindingDigest string       `json:"findingDigest"`
	Reason        string       `json:"reason,omitempty"`
}

type BaselineStatus struct {
	Path          string    `json:"path"`
	CreatedAt     time.Time `json:"createdAt"`
	PolicyDigest  string    `json:"policyDigest"`
	PolicyChanged bool      `json:"policyChanged"`
}

type Comparison struct {
	BaseRevision string `json:"baseRevision"`
	BaseCommit   string `json:"baseCommit"`
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
	New      int `json:"new"`
	Existing int `json:"existing"`
	Fixed    int `json:"fixed"`
	Stale    int `json:"stale"`
	Blocking int `json:"blocking"`
}

type Engine struct {
	registry *sdk.Registry
	version  string
}

func New(registry *sdk.Registry) *Engine { return &Engine{registry: registry, version: "dev"} }
func NewWithVersion(registry *sdk.Registry, version string) *Engine {
	return &Engine{registry: registry, version: version}
}

func (e *Engine) Validate(project *config.Project) ([]sdk.Rule, error) {
	rules, err := packs.Resolve(project, e.version)
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
	if len(project.Workspaces) > 0 {
		repo, err := repository.Open(project.Root, repository.Options{})
		if err != nil {
			return nil, fmt.Errorf("validate workspace repository: %w", err)
		}
		if _, err := buildWorkspaceScopes(project, repo); err != nil {
			return nil, err
		}
	}
	return rules, nil
}

func (e *Engine) Check(ctx context.Context, project *config.Project, options Options) (*Report, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	rules, err := e.Validate(project)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	digest, err := projectDigest(project, rules)
	if err != nil {
		return nil, err
	}
	now := options.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	repo, err := repository.Open(project.Root, repository.Options{BaseSHA: options.BaseSHA, MergeRequestTitle: options.MergeRequestTitle, Branch: options.Branch, GitContext: options.GitContext})
	if err != nil {
		return nil, err
	}
	findings, metrics, err := e.evaluate(ctx, project, rules, repo, now, digest)
	if err != nil {
		return nil, err
	}
	findings, waivers := applyWaivers(project, now, findings)
	report := &Report{
		ReportVersion: 2, Tool: Tool{Name: "hoolicy", Version: options.ToolVersion},
		Project: project.Project, GeneratedAt: now, ConfigDigest: digest, PolicyDigest: digest,
		Git: repo.Git(), FailOn: project.FailOn, Findings: findings, Waivers: waivers, Metrics: metrics,
	}
	baseline, baselinePath, err := loadBaseline(project)
	if err != nil {
		duplicateUnsafeMetadata := false
		for _, finding := range report.Findings {
			if finding.RuleID == "hoolicy.waivers" && strings.Contains(finding.Message, "path is unsafe") && strings.Contains(err.Error(), "path is unsafe") {
				duplicateUnsafeMetadata = true
			}
		}
		if !duplicateUnsafeMetadata {
			report.Findings = append(report.Findings, systemFinding("hoolicy.baseline", "Baseline is invalid: "+err.Error(), project.Baseline, "load"))
		}
	}
	if baseline != nil {
		if baseline.Project != project.Project {
			return nil, fmt.Errorf("baseline project %s does not match project %s", baseline.Project, project.Project)
		}
		report.Baseline = &BaselineStatus{Path: filepath.ToSlash(project.Baseline), CreatedAt: baseline.CreatedAt, PolicyDigest: baseline.PolicyDigest, PolicyChanged: baseline.PolicyDigest != digest}
		report.Changes = append(report.Changes, applyBaseline(report.Findings, baseline, rules)...)
		_ = baselinePath
	}
	if options.BaseSHA != "" {
		baseRepo, err := repository.OpenRevision(project.Root, options.BaseSHA, repository.Options{MergeRequestTitle: options.MergeRequestTitle})
		if err != nil {
			return nil, fmt.Errorf("compare base revision %s: %w", options.BaseSHA, err)
		}
		baseFindings, _, err := e.evaluate(ctx, project, rules, baseRepo, now, digest)
		if err != nil {
			return nil, fmt.Errorf("evaluate base revision %s: %w", options.BaseSHA, err)
		}
		report.Changes = append(report.Changes, applyGitComparison(report.Findings, baseFindings)...)
		report.Comparison = &Comparison{BaseRevision: options.BaseSHA, BaseCommit: baseRepo.Git().Commit}
	}
	sortFindings(report.Findings)
	sortChanges(report.Changes)
	report.Summary = summarize(report.Findings, report.Changes, project.FailOn)
	report.Summary.Rules = len(rules)
	return report, nil
}

func (e *Engine) evaluate(ctx context.Context, project *config.Project, rules []sdk.Rule, repo sdk.Repository, now time.Time, policyDigest string) ([]sdk.Finding, EvaluationMetrics, error) {
	started := time.Now()
	metrics := EvaluationMetrics{Files: len(repo.AllFiles()), Rules: []RuleMetric{}}
	for _, file := range repo.AllFiles() {
		metrics.Bytes += int64(len(file.Data))
		if int64(len(file.Data)) > project.Budgets.MaximumDocumentBytes {
			return nil, metrics, fmt.Errorf("resource budget exceeded: %s has %d bytes, maximum is %d", file.Path, len(file.Data), project.Budgets.MaximumDocumentBytes)
		}
	}
	if metrics.Files > project.Budgets.MaximumFiles {
		return nil, metrics, fmt.Errorf("resource budget exceeded: %d files, maximum is %d", metrics.Files, project.Budgets.MaximumFiles)
	}
	totalLimit, _ := time.ParseDuration(project.Budgets.MaximumTotalDuration)
	totalContext, cancelTotal := context.WithTimeout(ctx, totalLimit)
	defer cancelTotal()
	scopes, err := buildWorkspaceScopes(project, repo)
	if err != nil {
		return nil, metrics, err
	}
	for index := range scopes {
		scopes[index].repository = repository.Cached(scopes[index].repository, policyDigest)
	}
	findings := make([]sdk.Finding, 0)
	ruleLimit, _ := time.ParseDuration(project.Budgets.MaximumRuleDuration)
	for _, scope := range scopes {
		for _, rule := range rules {
			if scope.global && len(project.Workspaces) > 0 && rule.Pack != "" {
				continue
			}
			if !scope.global && rule.Pack == "" {
				continue
			}
			if !scope.global && !scope.packs[rule.Pack] {
				continue
			}
			if err := executionContextError(ctx, totalContext); err != nil {
				return nil, metrics, err
			}
			inputHitsBefore := repositoryInputCacheHits(scope.repository)
			inputs := len(scope.repository.AllFiles())
			if len(rule.Files) > 0 {
				matched, matchErr := scope.repository.Match(rule.Files, rule.Exclude)
				if matchErr != nil {
					return nil, metrics, matchErr
				}
				inputs = len(matched)
			}
			kind, _ := e.registry.Kind(rule.Kind)
			ruleContext, cancelRule := context.WithTimeout(totalContext, ruleLimit)
			ruleMetrics := &sdk.EvaluationMetrics{}
			input := sdk.EvalContext{Repository: scope.repository, Now: now, Parameters: scope.parameters, Metrics: ruleMetrics}
			ruleStarted := time.Now()
			type evaluationOutcome struct {
				findings []sdk.Finding
				err      error
			}
			outcomes := make(chan evaluationOutcome, 1)
			go func() {
				result, err := kind.Evaluate(ruleContext, input, rule)
				outcomes <- evaluationOutcome{findings: result, err: err}
			}()
			var result []sdk.Finding
			var evalErr error
			select {
			case outcome := <-outcomes:
				result, evalErr = outcome.findings, outcome.err
			case <-ruleContext.Done():
				duration := time.Since(ruleStarted)
				cancelRule()
				metrics.Rules = append(metrics.Rules, RuleMetric{RuleID: rule.ID, Workspace: scope.name, Inputs: inputs, DurationMilliseconds: duration.Milliseconds()})
				if err := ctx.Err(); err != nil {
					return nil, metrics, err
				}
				if errors.Is(totalContext.Err(), context.DeadlineExceeded) {
					return nil, metrics, fmt.Errorf("total execution budget exceeded: %w", totalContext.Err())
				}
				return nil, metrics, fmt.Errorf("rule %s exceeded execution budget %s", rule.ID, ruleLimit)
			}
			ruleContextErr := ruleContext.Err()
			cancelRule()
			duration := time.Since(ruleStarted)
			inputCacheHits := repositoryInputCacheHits(scope.repository) - inputHitsBefore
			metrics.Rules = append(metrics.Rules, RuleMetric{RuleID: rule.ID, Workspace: scope.name, Inputs: inputs, Findings: len(result), DurationMilliseconds: duration.Milliseconds(), InputCacheHits: inputCacheHits, ParseCacheHits: ruleMetrics.ParseCacheHits, CELCost: ruleMetrics.CELCost})
			metrics.InputCacheHits += inputCacheHits
			metrics.ParseCacheHits += ruleMetrics.ParseCacheHits
			if evalErr != nil {
				return nil, metrics, fmt.Errorf("rule %s: %w", rule.ID, evalErr)
			}
			if duration > ruleLimit || ruleContextErr != nil {
				return nil, metrics, fmt.Errorf("rule %s exceeded execution budget %s", rule.ID, ruleLimit)
			}
			for index := range result {
				if scope.global && len(project.Workspaces) > 0 {
					result[index].Workspace, result[index].Owner = routeGlobalFinding(project, result[index].Location.Path)
				} else {
					result[index].Workspace = scope.name
					result[index].Owner = scope.owner
				}
				result[index].Finalize(rule)
				findings = append(findings, result[index])
				if len(findings) > project.Budgets.MaximumFindings {
					return nil, metrics, fmt.Errorf("resource budget exceeded: findings exceed maximum %d", project.Budgets.MaximumFindings)
				}
			}
		}
	}
	metrics.DurationMilliseconds = time.Since(started).Milliseconds()
	if err := executionContextError(ctx, totalContext); err != nil {
		return nil, metrics, err
	}
	return findings, metrics, nil
}

func executionContextError(parent, total context.Context) error {
	if err := parent.Err(); err != nil {
		return err
	}
	if err := total.Err(); err != nil {
		return fmt.Errorf("total execution budget exceeded: %w", err)
	}
	return nil
}

func repositoryInputCacheHits(repo sdk.Repository) int {
	if measured, ok := repo.(interface{ InputCacheHits() int }); ok {
		return measured.InputCacheHits()
	}
	return 0
}

type workspaceScope struct {
	name       string
	owner      string
	repository sdk.Repository
	parameters map[string]any
	packs      map[string]bool
	global     bool
}

func buildWorkspaceScopes(project *config.Project, repo sdk.Repository) ([]workspaceScope, error) {
	if len(project.Workspaces) == 0 {
		packs := map[string]bool{}
		for _, pack := range project.Packs {
			packs[pack.Name] = true
		}
		return []workspaceScope{{repository: repo, parameters: project.Parameters, packs: packs, global: true}}, nil
	}
	byName := make(map[string]config.Workspace, len(project.Workspaces))
	for _, workspace := range project.Workspaces {
		byName[workspace.Name] = workspace
	}
	for _, file := range repo.AllFiles() {
		if workspaceMetadataPath(project, file.Path) {
			continue
		}
		owners := []string{}
		for _, workspace := range project.Workspaces {
			matched, err := repository.Matches(file.Path, workspace.Paths)
			if err != nil {
				return nil, err
			}
			if matched {
				owners = append(owners, workspace.Name)
			}
		}
		if len(owners) == 0 {
			return nil, fmt.Errorf("unowned workspace path: %s", file.Path)
		}
		if len(owners) > 1 {
			return nil, fmt.Errorf("workspace scope overlap for %s: %s", file.Path, strings.Join(owners, ", "))
		}
	}
	result := make([]workspaceScope, 0, len(project.Workspaces)+1)
	result = append(result, workspaceScope{name: "root", owner: "repository", repository: repo, parameters: project.Parameters, global: true})
	for _, workspace := range project.Workspaces {
		patterns := append([]string(nil), workspace.Paths...)
		parameters := map[string]any{}
		for key, value := range project.Parameters {
			parameters[key] = value
		}
		visited := map[string]bool{}
		var include func(string)
		include = func(name string) {
			if visited[name] {
				return
			}
			visited[name] = true
			dependency := byName[name]
			patterns = append(patterns, dependency.Paths...)
			for key, value := range dependency.Parameters {
				parameters[key] = value
			}
			for _, nested := range dependency.DependsOn {
				include(nested)
			}
		}
		for _, dependency := range workspace.DependsOn {
			include(dependency)
		}
		for key, value := range workspace.Parameters {
			parameters[key] = value
		}
		subset, err := repository.Subset(repo, patterns)
		if err != nil {
			return nil, err
		}
		packs := map[string]bool{}
		for _, name := range workspace.Packs {
			packs[name] = true
		}
		result = append(result, workspaceScope{name: workspace.Name, owner: workspace.Owner, repository: subset, parameters: parameters, packs: packs})
	}
	return result, nil
}

func routeGlobalFinding(project *config.Project, path string) (string, string) {
	if path != "" {
		for _, workspace := range project.Workspaces {
			if matched, _ := repository.Matches(path, workspace.Paths); matched {
				return workspace.Name, workspace.Owner
			}
		}
	}
	return "root", "repository"
}

func workspaceMetadataPath(project *config.Project, path string) bool {
	path = filepath.ToSlash(path)
	configPath, _ := filepath.Rel(project.Root, project.Path)
	return path == filepath.ToSlash(configPath) || path == config.DefaultLockfile || path == ".hoolicy" || strings.HasPrefix(path, ".hoolicy/")
}

func summarize(findings []sdk.Finding, changes []Change, failOn sdk.Severity) Summary {
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
			summary.New += 0
			continue
		}
		if item.State == sdk.FindingExisting {
			summary.Existing++
		} else {
			summary.New++
		}
		if item.State != sdk.FindingExisting && item.Severity.Rank() >= failOn.Rank() {
			summary.Blocking++
		}
	}
	for _, change := range changes {
		if change.State == "fixed" {
			summary.Fixed++
		} else if change.State == "stale" {
			summary.Stale++
		}
	}
	return summary
}

func loadBaseline(project *config.Project) (*config.BaselineFile, string, error) {
	_, path, err := safepath.Existing(project.Root, project.Baseline)
	if errors.Is(err, os.ErrNotExist) {
		return nil, "", nil
	}
	if err != nil {
		return nil, "", fmt.Errorf("baseline path is unsafe: %w", err)
	}
	baseline, err := config.LoadBaseline(path)
	if err != nil {
		return nil, path, fmt.Errorf("load baseline: %w", err)
	}
	return baseline, path, nil
}

func applyBaseline(findings []sdk.Finding, baseline *config.BaselineFile, rules []sdk.Rule) []Change {
	entries := make(map[string]config.BaselineEntry, len(baseline.Entries))
	for _, entry := range baseline.Entries {
		entries[entry.Fingerprint] = entry
	}
	current := make(map[string]*sdk.Finding, len(findings))
	for index := range findings {
		finding := &findings[index]
		current[finding.Fingerprint] = finding
		entry, exists := entries[finding.Fingerprint]
		if !exists || finding.Waived || strings.HasPrefix(finding.RuleID, "hoolicy.") {
			continue
		}
		if baselineEntryMatches(entry, *finding) {
			finding.State = sdk.FindingExisting
			finding.StateSource = "baseline"
		}
	}
	active := make(map[string]string, len(rules))
	for _, rule := range rules {
		active[rule.ID] = sdk.RuleDigest(rule)
	}
	changes := make([]Change, 0)
	for _, entry := range baseline.Entries {
		finding := current[entry.Fingerprint]
		if finding != nil && baselineEntryMatches(entry, *finding) {
			continue
		}
		change := Change{Source: "baseline", Fingerprint: entry.Fingerprint, RuleID: entry.RuleID, Severity: entry.Severity, PolicyDigest: entry.PolicyDigest, FindingDigest: entry.FindingDigest}
		switch {
		case active[entry.RuleID] == "":
			change.State, change.Reason = "stale", "rule no longer exists"
		case active[entry.RuleID] != entry.PolicyDigest:
			change.State, change.Reason = "stale", "policy digest changed"
		case finding != nil:
			change.State, change.Reason = "stale", "finding changed materially"
		default:
			change.State, change.Reason = "fixed", "fingerprint no longer reproduces"
		}
		changes = append(changes, change)
	}
	return changes
}

func baselineEntryMatches(entry config.BaselineEntry, finding sdk.Finding) bool {
	return entry.RuleID == finding.RuleID && entry.Severity == finding.Severity && entry.PolicyDigest == finding.PolicyDigest && entry.FindingDigest == finding.FindingDigest
}

func applyGitComparison(findings, baseFindings []sdk.Finding) []Change {
	base := make(map[string]sdk.Finding, len(baseFindings))
	for _, finding := range baseFindings {
		if !strings.HasPrefix(finding.RuleID, "hoolicy.") {
			base[finding.Fingerprint] = finding
		}
	}
	current := make(map[string]sdk.Finding, len(findings))
	for index := range findings {
		finding := &findings[index]
		current[finding.Fingerprint] = *finding
		previous, exists := base[finding.Fingerprint]
		if !exists || finding.Waived || finding.State == sdk.FindingExisting || strings.HasPrefix(finding.RuleID, "hoolicy.") {
			continue
		}
		if previous.PolicyDigest == finding.PolicyDigest && previous.FindingDigest == finding.FindingDigest && previous.Severity == finding.Severity {
			finding.State = sdk.FindingExisting
			finding.StateSource = "git"
		}
	}
	var changes []Change
	for fingerprint, previous := range base {
		finding, exists := current[fingerprint]
		if exists && finding.PolicyDigest == previous.PolicyDigest && finding.FindingDigest == previous.FindingDigest && finding.Severity == previous.Severity {
			continue
		}
		state, reason := "fixed", "fingerprint no longer reproduces"
		if exists {
			state, reason = "stale", "finding changed materially"
		}
		changes = append(changes, Change{State: state, Source: "git", Fingerprint: previous.Fingerprint, RuleID: previous.RuleID, Severity: previous.Severity, PolicyDigest: previous.PolicyDigest, FindingDigest: previous.FindingDigest, Reason: reason})
	}
	return changes
}

func sortChanges(changes []Change) {
	sort.Slice(changes, func(i, j int) bool {
		if changes[i].State != changes[j].State {
			return changes[i].State < changes[j].State
		}
		if changes[i].Source != changes[j].Source {
			return changes[i].Source < changes[j].Source
		}
		if changes[i].RuleID != changes[j].RuleID {
			return changes[i].RuleID < changes[j].RuleID
		}
		return changes[i].Fingerprint < changes[j].Fingerprint
	})
}

func applyWaivers(project *config.Project, now time.Time, findings []sdk.Finding) ([]sdk.Finding, []config.Waiver) {
	_, path, pathErr := safepath.Existing(project.Root, project.Waivers)
	if errors.Is(pathErr, os.ErrNotExist) {
		return findings, []config.Waiver{}
	}
	if pathErr != nil {
		return append(findings, systemFinding("hoolicy.waivers", "Waiver path is unsafe: "+pathErr.Error(), project.Waivers, "path")), []config.Waiver{}
	}
	waiverFile, err := config.LoadWaivers(path)
	if err != nil {
		return append(findings, systemFinding("hoolicy.waivers", "Waiver file is invalid: "+err.Error(), project.Waivers, "parse")), []config.Waiver{}
	}
	waivers := append([]config.Waiver{}, waiverFile.Waivers...)
	sort.Slice(waivers, func(i, j int) bool { return waivers[i].ID < waivers[j].ID })
	seen := map[string]bool{}
	for _, waiver := range waiverFile.Waivers {
		if seen[waiver.ID] {
			findings = append(findings, systemFinding("hoolicy.waivers", "Duplicate waiver ID: "+waiver.ID, project.Waivers, waiver.ID))
			continue
		}
		seen[waiver.ID] = true
		if err := config.ValidateWaiverForProject(waiver, now, project.RequireWaiverApprover); err != nil {
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
				item.State = sdk.FindingWaived
				item.StateSource = "waiver"
				used = true
			}
		}
		if !used {
			findings = append(findings, systemFinding("hoolicy.waivers", "Stale waiver matches no current finding: "+waiver.ID, project.Waivers, waiver.ID))
		}
	}
	return findings, waivers
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

// ProjectDigest computes the policy identity for a validated active rule set.
// Callers that need the active rules should obtain them through Validate first.
func ProjectDigest(project *config.Project, rules []sdk.Rule) (string, error) {
	return projectDigest(project, rules)
}

func projectDigest(project *config.Project, rules []sdk.Rule) (string, error) {
	hash := sha256.New()
	writeInput := func(label string, data []byte) {
		hash.Write([]byte(label))
		hash.Write([]byte{0})
		hash.Write(data)
		hash.Write([]byte{0})
	}
	for _, input := range []struct{ label, path string }{
		{label: config.DefaultFilename, path: project.Path},
		{label: config.DefaultLockfile, path: filepath.Join(project.Root, config.DefaultLockfile)},
	} {
		data, exists, err := readDigestFile(input.path)
		if err != nil {
			return "", err
		}
		if exists {
			writeInput(input.label, data)
		}
	}
	waiverLabel := filepath.ToSlash(project.Waivers)
	_, waiverPath, waiverPathErr := safepath.Existing(project.Root, project.Waivers)
	if waiverPathErr == nil {
		data, _, err := readDigestFile(waiverPath)
		if err != nil {
			return "", err
		}
		writeInput(waiverLabel, data)
	} else if !errors.Is(waiverPathErr, os.ErrNotExist) {
		// Unsafe waiver metadata is represented without following or reading it.
		// applyWaivers emits the actionable blocking finding.
		writeInput(waiverLabel, []byte("unsafe"))
	}
	evidenceRelative := project.Evidence
	if evidenceRelative == "" {
		evidenceRelative = config.DefaultEvidence
	}
	evidenceLabel := filepath.ToSlash(evidenceRelative)
	_, evidencePath, evidencePathErr := safepath.Existing(project.Root, evidenceRelative)
	if evidencePathErr == nil {
		data, _, err := readDigestFile(evidencePath)
		if err != nil {
			return "", err
		}
		writeInput(evidenceLabel, data)
	} else if !errors.Is(evidencePathErr, os.ErrNotExist) {
		writeInput(evidenceLabel, []byte("unsafe"))
	}
	active, err := json.Marshal(rules)
	if err != nil {
		return "", fmt.Errorf("encode active policy digest: %w", err)
	}
	hash.Write(active)
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

func readDigestFile(path string) ([]byte, bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, false, fmt.Errorf("%s: expected a regular file, symbolic links are forbidden", path)
	}
	data, err := os.ReadFile(path)
	return data, true, err
}
