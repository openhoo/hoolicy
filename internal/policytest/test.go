package policytest

import (
	"context"
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
	Name       string            `yaml:"name"`
	Rule       string            `yaml:"rule"`
	Outcome    string            `yaml:"outcome"`
	Files      map[string]string `yaml:"files,omitempty"`
	Branch     string            `yaml:"branch,omitempty"`
	MRTitle    string            `yaml:"mergeRequestTitle,omitempty"`
	Parameters map[string]any    `yaml:"parameters,omitempty"`
}

type Result struct {
	Cases  int
	Passed int
	Errors []string
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
		if testCase.Name == "" || testCase.Rule == "" || (testCase.Outcome != "pass" && testCase.Outcome != "fail") {
			result.Errors = append(result.Errors, "test cases require name, rule, and pass/fail outcome")
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
		coverage[testCase.Rule][testCase.Outcome] = true
		parameters := merge(tests.Parameters, testCase.Parameters)
		rules, instantiateErr := pack.Instantiate(parameters)
		if instantiateErr != nil {
			result.Errors = append(result.Errors, testCase.Name+": "+instantiateErr.Error())
			continue
		}
		var selected *sdk.Rule
		for index := range rules {
			if rules[index].ID == testCase.Rule {
				selected = &rules[index]
				break
			}
		}
		if selected == nil {
			result.Errors = append(result.Errors, testCase.Name+": unknown rule "+testCase.Rule)
			continue
		}
		passed, runErr := runCase(ctx, *selected, testCase, registry)
		if runErr != nil {
			result.Errors = append(result.Errors, testCase.Name+": "+runErr.Error())
			continue
		}
		if !passed {
			result.Errors = append(result.Errors, fmt.Sprintf("%s: expected %s outcome", testCase.Name, testCase.Outcome))
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

func runCase(ctx context.Context, rule sdk.Rule, testCase Case, registry *sdk.Registry) (bool, error) {
	root, err := os.MkdirTemp("", "hoolicy-policy-test-*")
	if err != nil {
		return false, err
	}
	defer os.RemoveAll(root)
	for path, content := range testCase.Files {
		clean, err := safeFixturePath(path)
		if err != nil {
			return false, err
		}
		if reservedFixturePath(clean) {
			return false, fmt.Errorf("fixture path %s is reserved for the test harness", filepath.ToSlash(clean))
		}
		absolute := filepath.Join(root, clean)
		if err := os.MkdirAll(filepath.Dir(absolute), 0o755); err != nil {
			return false, err
		}
		if err := os.WriteFile(absolute, []byte(content), 0o644); err != nil {
			return false, err
		}
	}
	project := config.Project{Version: 1, Project: "fixture", FailOn: sdk.SeverityInfo, Rules: []sdk.Rule{rule}, Root: root, Path: filepath.Join(root, "hoolicy.yaml")}
	if err := config.SaveProject(project.Path, project); err != nil {
		return false, err
	}
	loaded, err := config.LoadProject(project.Path)
	if err != nil {
		return false, err
	}
	const fixtureCommit = "0000000000000000000000000000000000000001"
	gitContext := sdk.GitContext{
		Branch: fallback(testCase.Branch, "main"), Commit: fixtureCommit,
		CommitSubjects:    []sdk.Commit{{SHA: fixtureCommit, Subject: "test: fixture"}},
		MergeRequestTitle: testCase.MRTitle, Properties: make(map[string]any),
	}
	report, err := engine.New(registry).Check(ctx, loaded, engine.Options{
		Now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), ToolVersion: "test", GitContext: &gitContext,
	})
	if err != nil {
		return false, err
	}
	failed := false
	for _, item := range report.Findings {
		if item.RuleID != rule.ID {
			return false, fmt.Errorf("unexpected harness finding %s: %s", item.RuleID, item.Message)
		}
		if !item.Waived && item.Severity.Rank() >= loaded.FailOn.Rank() {
			failed = true
		}
	}
	passed := (testCase.Outcome == "fail" && failed) || (testCase.Outcome == "pass" && !failed)
	if !passed {
		messages := make([]string, 0, len(report.Findings))
		for _, item := range report.Findings {
			messages = append(messages, item.RuleID+": "+item.Message)
		}
		return false, fmt.Errorf("expected %s outcome; findings: %s", testCase.Outcome, strings.Join(messages, " | "))
	}
	return true, nil
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
	if strings.TrimSpace(path) == "" || filepath.IsAbs(path) {
		return "", fmt.Errorf("fixture path must be relative")
	}
	clean := filepath.Clean(path)
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("fixture path escapes root")
	}
	return clean, nil
}

func reservedFixturePath(path string) bool {
	path = filepath.ToSlash(path)
	return path == config.DefaultFilename || path == config.DefaultLockfile || path == config.DefaultWaivers || strings.HasPrefix(path, ".hoolicy/vendor/")
}
