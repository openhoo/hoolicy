package policytest

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/openhoo/hoolicy/internal/config"
	"github.com/openhoo/hoolicy/internal/engine"
	"github.com/openhoo/hoolicy/sdk"
)

type File struct {
	Version    int            `yaml:"version"`
	Parameters map[string]any `yaml:"parameters,omitempty"`
	Cases      []Case         `yaml:"cases"`
}

type Case struct {
	Name          string              `yaml:"name"`
	Rule          string              `yaml:"rule"`
	Outcome       string              `yaml:"outcome"`
	Files         map[string]string   `yaml:"files,omitempty"`
	Documents     map[string][]string `yaml:"documents,omitempty"`
	Branch        string              `yaml:"branch,omitempty"`
	Commit        string              `yaml:"commit,omitempty"`
	Commits       []sdk.Commit        `yaml:"commits,omitempty"`
	Dirty         bool                `yaml:"dirty,omitempty"`
	GitProperties map[string]any      `yaml:"gitProperties,omitempty"`
	MRTitle       string              `yaml:"mergeRequestTitle,omitempty"`
	Now           string              `yaml:"now,omitempty"`
	Parameters    map[string]any      `yaml:"parameters,omitempty"`
	Waivers       []config.Waiver     `yaml:"waivers,omitempty"`
	WaiveFindings bool                `yaml:"waiveFindings,omitempty"`
	Expect        []ExpectedFinding   `yaml:"expect,omitempty"`
	FindingCount  *int                `yaml:"findingCount,omitempty"`
	ErrorContains string              `yaml:"errorContains,omitempty"`
}

type ExpectedFinding struct {
	RuleID          string `yaml:"ruleId,omitempty"`
	Path            string `yaml:"path,omitempty"`
	Line            int    `yaml:"line,omitempty"`
	Column          int    `yaml:"column,omitempty"`
	MessageContains string `yaml:"messageContains,omitempty"`
	Key             string `yaml:"key,omitempty"`
	Waived          *bool  `yaml:"waived,omitempty"`
	HasFix          *bool  `yaml:"hasFix,omitempty"`
}

type Result struct {
	Cases  int
	Passed int
	Errors []string
}

type Snapshot struct {
	Version int            `json:"version"`
	Pack    string         `json:"pack"`
	Release string         `json:"release"`
	Cases   []SnapshotCase `json:"cases"`
}

type SnapshotCase struct {
	Name     string            `json:"name"`
	RuleID   string            `json:"ruleId"`
	Outcome  string            `json:"outcome"`
	Findings []SnapshotFinding `json:"findings"`
	Error    string            `json:"error,omitempty"`
}

type SnapshotFinding struct {
	RuleID      string       `json:"ruleId"`
	Severity    sdk.Severity `json:"severity"`
	Path        string       `json:"path,omitempty"`
	Line        int          `json:"line,omitempty"`
	Column      int          `json:"column,omitempty"`
	Message     string       `json:"message"`
	Key         string       `json:"key,omitempty"`
	Fingerprint string       `json:"fingerprint"`
	Waived      bool         `json:"waived"`
	HasFix      bool         `json:"hasFix"`
}

func BuildSnapshot(ctx context.Context, packPath string, registry *sdk.Registry) (*Snapshot, error) {
	pack, err := config.LoadPack(packPath)
	if err != nil {
		return nil, err
	}
	var tests File
	if err := config.LoadYAMLStrict(filepath.Join(packPath, "tests", "cases.yaml"), &tests); err != nil {
		return nil, err
	}
	snapshot := &Snapshot{Version: 1, Pack: pack.Name, Release: pack.Release, Cases: make([]SnapshotCase, 0, len(tests.Cases))}
	for _, testCase := range tests.Cases {
		selected, err := instantiateRule(pack, merge(tests.Parameters, testCase.Parameters), testCase.Rule)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", testCase.Name, err)
		}
		result, runErr := runCase(ctx, selected, testCase, registry)
		caseSnapshot := SnapshotCase{Name: testCase.Name, RuleID: testCase.Rule, Outcome: testCase.Outcome, Findings: make([]SnapshotFinding, 0)}
		if runErr != nil {
			caseSnapshot.Error = runErr.Error()
		} else {
			for _, finding := range result.Findings {
				caseSnapshot.Findings = append(caseSnapshot.Findings, SnapshotFinding{RuleID: finding.RuleID, Severity: finding.Severity, Path: finding.Location.Path, Line: finding.Location.Line, Column: finding.Location.Column, Message: finding.Message, Key: finding.Key, Fingerprint: finding.Fingerprint, Waived: finding.Waived, HasFix: finding.Fix != nil})
			}
		}
		snapshot.Cases = append(snapshot.Cases, caseSnapshot)
	}
	sort.Slice(snapshot.Cases, func(i, j int) bool {
		if snapshot.Cases[i].RuleID != snapshot.Cases[j].RuleID {
			return snapshot.Cases[i].RuleID < snapshot.Cases[j].RuleID
		}
		return snapshot.Cases[i].Name < snapshot.Cases[j].Name
	})
	return snapshot, nil
}

func SnapshotJSON(snapshot *Snapshot) ([]byte, error) {
	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func Run(ctx context.Context, packPath string, registry *sdk.Registry) Result {
	pack, err := config.LoadPack(packPath)
	if err != nil {
		return Result{Errors: []string{err.Error()}}
	}
	testsPath := filepath.Join(packPath, "tests", "cases.yaml")
	var tests File
	if err := config.LoadYAMLStrict(testsPath, &tests); err != nil {
		return Result{Errors: []string{err.Error()}}
	}
	if tests.Version != 1 {
		return Result{Errors: []string{"policy test version must be 1"}}
	}
	if len(tests.Cases) == 0 {
		return Result{Errors: []string{"policy tests require at least one case"}}
	}
	coverage := map[string]map[string]bool{}
	result := Result{Cases: len(tests.Cases)}
	knownRules := make(map[string]bool, len(pack.Rules))
	for _, rule := range pack.Rules {
		knownRules[rule.ID] = true
	}
	caseNames := make(map[string]bool, len(tests.Cases))
	for _, testCase := range tests.Cases {
		if err := ctx.Err(); err != nil {
			result.Errors = append(result.Errors, err.Error())
			break
		}
		if testCase.Name == "" || testCase.Rule == "" || (testCase.Outcome != "pass" && testCase.Outcome != "fail" && testCase.Outcome != "error") {
			result.Errors = append(result.Errors, "test cases require name, rule, and pass/fail/error outcome")
			continue
		}
		if caseNames[testCase.Name] {
			result.Errors = append(result.Errors, testCase.Name+": duplicate test case name")
			continue
		}
		caseNames[testCase.Name] = true
		if !knownRules[testCase.Rule] {
			result.Errors = append(result.Errors, testCase.Name+": unknown rule "+testCase.Rule)
			continue
		}
		if coverage[testCase.Rule] == nil {
			coverage[testCase.Rule] = map[string]bool{}
		}
		if testCase.Outcome != "error" {
			coverage[testCase.Rule][testCase.Outcome] = true
		}
		selected, instantiateErr := instantiateRule(pack, merge(tests.Parameters, testCase.Parameters), testCase.Rule)
		if instantiateErr != nil {
			result.Errors = append(result.Errors, testCase.Name+": "+instantiateErr.Error())
			continue
		}
		if err := evaluateTestCase(ctx, selected, testCase, registry); err != nil {
			result.Errors = append(result.Errors, testCase.Name+": "+err.Error())
			continue
		}
		result.Passed++
	}
	for _, rule := range pack.Rules {
		if !coverage[rule.ID]["pass"] || !coverage[rule.ID]["fail"] {
			result.Errors = append(result.Errors, rule.ID+": needs at least one pass and one fail case")
		}
	}
	sort.Strings(result.Errors)
	return result
}

func instantiateRule(pack *config.Pack, parameters map[string]any, ruleID string) (sdk.Rule, error) {
	rules, err := pack.Instantiate(parameters)
	if err != nil {
		return sdk.Rule{}, err
	}
	for _, rule := range rules {
		if rule.ID == ruleID {
			return rule, nil
		}
	}
	return sdk.Rule{}, fmt.Errorf("unknown rule %s", ruleID)
}

func evaluateTestCase(ctx context.Context, rule sdk.Rule, testCase Case, registry *sdk.Registry) error {
	report, runErr := runCase(ctx, rule, testCase, registry)
	if testCase.Outcome == "error" {
		if runErr == nil {
			return fmt.Errorf("expected evaluation error")
		}
		if testCase.ErrorContains != "" && !strings.Contains(runErr.Error(), testCase.ErrorContains) {
			return fmt.Errorf("error does not contain %s: %w", testCase.ErrorContains, runErr)
		}
		return nil
	}
	if runErr != nil {
		return runErr
	}
	return assertFindings(rule, testCase, report)
}

func runCase(ctx context.Context, rule sdk.Rule, testCase Case, registry *sdk.Registry) (*engine.Report, error) {
	root, err := os.MkdirTemp("", "hoolicy-policy-test-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(root)
	if err := writeCaseFixtures(root, testCase); err != nil {
		return nil, err
	}
	project := config.Project{Version: 1, Project: "fixture", FailOn: sdk.SeverityInfo, Rules: []sdk.Rule{rule}, Root: root, Path: filepath.Join(root, "hoolicy.yaml")}
	if err := config.SaveProject(project.Path, project); err != nil {
		return nil, err
	}
	if len(testCase.Waivers) > 0 {
		waiverPath := filepath.Join(root, config.DefaultWaivers)
		if err := os.MkdirAll(filepath.Dir(waiverPath), 0o755); err != nil {
			return nil, err
		}
		if err := config.SaveWaivers(waiverPath, config.WaiverFile{Version: config.CurrentVersion, Waivers: testCase.Waivers}); err != nil {
			return nil, err
		}
	}
	loaded, err := config.LoadProject(project.Path)
	if err != nil {
		return nil, err
	}
	gitContext, now, err := fixtureContext(testCase)
	if err != nil {
		return nil, err
	}
	report, err := engine.New(registry).Check(ctx, loaded, engine.Options{
		Now: now, ToolVersion: "test", GitContext: &gitContext,
	})
	if err != nil {
		return nil, err
	}
	if !testCase.WaiveFindings {
		return report, nil
	}
	return rerunWithFixtureWaiver(ctx, loaded, rule, testCase, report, registry, gitContext, now)
}

func writeCaseFixtures(root string, testCase Case) error {
	filePaths := sortedFixturePaths(testCase.Files)
	for _, path := range filePaths {
		if err := writeFixture(root, path, testCase.Files[path]); err != nil {
			return err
		}
	}
	documentPaths := sortedFixturePaths(testCase.Documents)
	for _, path := range documentPaths {
		if _, exists := testCase.Files[path]; exists {
			return fmt.Errorf("fixture path %s is present in both files and documents", path)
		}
		content := strings.Join(testCase.Documents[path], "\n---\n")
		if !strings.HasSuffix(content, "\n") {
			content += "\n"
		}
		if err := writeFixture(root, path, content); err != nil {
			return err
		}
	}
	return nil
}

func sortedFixturePaths[T any](files map[string]T) []string {
	paths := make([]string, 0, len(files))
	for path := range files {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	return paths
}

func writeFixture(root, path, content string) error {
	clean, err := safeFixturePath(path)
	if err != nil {
		return err
	}
	if reservedFixturePath(clean) {
		return fmt.Errorf("fixture path %s is reserved for the test harness", filepath.ToSlash(clean))
	}
	absolute := filepath.Join(root, clean)
	if err := os.MkdirAll(filepath.Dir(absolute), 0o755); err != nil {
		return err
	}
	return os.WriteFile(absolute, []byte(content), 0o644)
}

func fixtureContext(testCase Case) (sdk.GitContext, time.Time, error) {
	const fixtureCommit = "0000000000000000000000000000000000000001"
	commit := fallback(testCase.Commit, fixtureCommit)
	commits := testCase.Commits
	if len(commits) == 0 {
		commits = []sdk.Commit{{SHA: commit, Subject: "test: fixture"}}
	}
	properties := testCase.GitProperties
	if properties == nil {
		properties = make(map[string]any)
	}
	gitContext := sdk.GitContext{
		Branch: fallback(testCase.Branch, "main"), Commit: commit, Dirty: testCase.Dirty,
		CommitSubjects: commits, MergeRequestTitle: testCase.MRTitle, Properties: properties,
	}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if testCase.Now == "" {
		return gitContext, now, nil
	}
	parsed, err := time.Parse(time.RFC3339, testCase.Now)
	if err != nil {
		return sdk.GitContext{}, time.Time{}, fmt.Errorf("now must be RFC3339: %w", err)
	}
	return gitContext, parsed, nil
}

func rerunWithFixtureWaiver(ctx context.Context, project *config.Project, rule sdk.Rule, testCase Case, report *engine.Report, registry *sdk.Registry, gitContext sdk.GitContext, now time.Time) (*engine.Report, error) {
	fingerprints := make([]string, 0, len(report.Findings))
	for _, finding := range report.Findings {
		if finding.RuleID == rule.ID {
			fingerprints = append(fingerprints, finding.Fingerprint)
		}
	}
	if len(fingerprints) == 0 {
		return nil, fmt.Errorf("waiveFindings requires at least one rule finding")
	}
	waiver := config.Waiver{ID: "fixture.waiver", Rule: rule.ID, Fingerprints: fingerprints, Reason: "Policy fixture verifies explicit waiver behavior.", Owner: "policy-test@example.com", Ticket: "https://issues.example.com/POLICY-1", Created: config.Date{Time: now.Add(-24 * time.Hour)}, Expires: config.Date{Time: now.Add(30 * 24 * time.Hour)}}
	waiverPath := filepath.Join(project.Root, config.DefaultWaivers)
	if err := os.MkdirAll(filepath.Dir(waiverPath), 0o755); err != nil {
		return nil, err
	}
	waivers := append(append([]config.Waiver(nil), testCase.Waivers...), waiver)
	if err := config.SaveWaivers(waiverPath, config.WaiverFile{Version: config.CurrentVersion, Waivers: waivers}); err != nil {
		return nil, err
	}
	return engine.New(registry).Check(ctx, project, engine.Options{Now: now, ToolVersion: "test", GitContext: &gitContext})
}

func assertFindings(rule sdk.Rule, testCase Case, report *engine.Report) error {
	failed := false
	for _, item := range report.Findings {
		if item.RuleID != rule.ID {
			return fmt.Errorf("unexpected harness finding %s: %s", item.RuleID, item.Message)
		}
		if !item.Waived && item.Severity.Rank() >= report.FailOn.Rank() {
			failed = true
		}
	}
	passed := (testCase.Outcome == "fail" && failed) || (testCase.Outcome == "pass" && !failed)
	if !passed {
		messages := make([]string, 0, len(report.Findings))
		for _, item := range report.Findings {
			messages = append(messages, item.RuleID+": "+item.Message)
		}
		return fmt.Errorf("expected %s outcome; findings: %s", testCase.Outcome, strings.Join(messages, " | "))
	}
	if testCase.FindingCount != nil && len(report.Findings) != *testCase.FindingCount {
		return fmt.Errorf("findingCount is %d, got %d", *testCase.FindingCount, len(report.Findings))
	}
	used := make(map[int]bool)
	for _, expected := range testCase.Expect {
		matched := -1
		for index, finding := range report.Findings {
			if used[index] || !matchesExpected(rule.ID, expected, finding) {
				continue
			}
			matched = index
			break
		}
		if matched < 0 {
			return fmt.Errorf("expected finding was not produced: %#v", expected)
		}
		used[matched] = true
	}
	return nil
}

func matchesExpected(defaultRule string, expected ExpectedFinding, finding sdk.Finding) bool {
	ruleID := fallback(expected.RuleID, defaultRule)
	if finding.RuleID != ruleID || expected.Path != "" && finding.Location.Path != expected.Path || expected.Line > 0 && finding.Location.Line != expected.Line || expected.Column > 0 && finding.Location.Column != expected.Column || expected.Key != "" && finding.Key != expected.Key || expected.MessageContains != "" && !strings.Contains(finding.Message, expected.MessageContains) {
		return false
	}
	if expected.Waived != nil && finding.Waived != *expected.Waived {
		return false
	}
	if expected.HasFix != nil && (finding.Fix != nil) != *expected.HasFix {
		return false
	}
	return true
}

func merge(left, right map[string]any) map[string]any {
	result := map[string]any{}
	for key, value := range left {
		result[key] = value
	}
	for key, value := range right {
		result[key] = value
	}
	return result
}
func fallback(value, defaultValue string) string {
	if strings.TrimSpace(value) == "" {
		return defaultValue
	}
	return value
}
func safeFixturePath(path string) (string, error) {
	if strings.TrimSpace(path) == "" || strings.TrimSpace(path) != path || strings.HasPrefix(path, "/") || filepath.IsAbs(path) || fixtureWindowsVolume(path) || strings.ContainsAny(path, "\\\x00") {
		return "", fmt.Errorf("fixture path must be relative")
	}
	portable := filepath.FromSlash(path)
	clean := filepath.Clean(portable)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("fixture path escapes root")
	}
	if clean != portable {
		return "", fmt.Errorf("fixture path must be canonical")
	}
	return clean, nil
}

func fixtureWindowsVolume(path string) bool {
	return len(path) >= 2 && path[1] == ':' && (path[0] >= 'A' && path[0] <= 'Z' || path[0] >= 'a' && path[0] <= 'z')
}

func reservedFixturePath(path string) bool {
	path = filepath.ToSlash(path)
	return path == config.DefaultFilename || path == config.DefaultLockfile || path == config.DefaultWaivers || strings.HasPrefix(path, ".hoolicy/vendor/")
}
