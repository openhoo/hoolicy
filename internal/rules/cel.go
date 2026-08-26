package rules

import (
	"context"
	"fmt"
	"reflect"
	"strings"

	"cel.dev/cel-go/cel"
	"github.com/openhoo/hoolicy/internal/document"
	"github.com/openhoo/hoolicy/sdk"
)

type CEL struct{}

type celSpec struct {
	Format     string `yaml:"format,omitempty"`
	Expression string `yaml:"expression"`
	Message    string `yaml:"message"`
	CostLimit  uint64 `yaml:"costLimit,omitempty"`
}

func (CEL) Validate(rule sdk.Rule) error {
	if err := requireFiles(rule); err != nil {
		return err
	}
	var spec celSpec
	if err := decodeSpec(rule, &spec); err != nil {
		return err
	}
	if strings.TrimSpace(spec.Expression) == "" || strings.TrimSpace(spec.Message) == "" {
		return fmt.Errorf("rule %s: structured.cel requires expression and message", rule.ID)
	}
	_, _, err := compileCEL(spec)
	return err
}

func (CEL) Evaluate(_ context.Context, input sdk.EvalContext, rule sdk.Rule) ([]sdk.Finding, error) {
	var spec celSpec
	if err := decodeSpec(rule, &spec); err != nil {
		return nil, err
	}
	_, program, err := compileCEL(spec)
	if err != nil {
		return nil, fmt.Errorf("rule %s: %w", rule.ID, err)
	}
	files, err := input.Repository.Match(rule.Files, rule.Exclude)
	if err != nil {
		return nil, err
	}
	fileValues := make([]any, 0, len(files))
	documents := make([]any, 0)
	for _, file := range files {
		fileValues = append(fileValues, map[string]any{"path": file.Path, "size": int64(len(file.Data)), "sha256": file.SHA256()})
		parsed, parseErr := document.Parse(file, spec.Format)
		if parseErr != nil {
			return nil, parseErr
		}
		for _, item := range parsed {
			documents = append(documents, map[string]any{
				"path": item.Path, "index": int64(item.Index), "line": int64(item.Line),
				"column": int64(item.Column), "data": item.Data,
			})
		}
	}
	git := input.Repository.Git()
	variables := map[string]any{
		"repo":  map[string]any{"root": input.Repository.Root(), "project": filepathBase(input.Repository.Root())},
		"git":   map[string]any{"branch": git.Branch, "commit": git.Commit, "dirty": git.Dirty, "mergeRequestTitle": git.MergeRequestTitle},
		"files": fileValues, "documents": documents, "items": documents,
		"params": input.Parameters, "now": input.Now,
	}
	result, _, err := program.Eval(variables)
	if err != nil {
		return nil, fmt.Errorf("rule %s: CEL evaluation: %w", rule.ID, err)
	}
	if boolean, ok := result.Value().(bool); ok {
		if boolean {
			return nil, nil
		}
		return []sdk.Finding{finding(rule, spec.Message, "", "cel", 0, 0)}, nil
	}
	native, err := result.ConvertToNative(reflect.TypeOf([]any{}))
	if err != nil {
		return nil, fmt.Errorf("rule %s: CEL must return bool or list of violations: %w", rule.ID, err)
	}
	entries, ok := native.([]any)
	if !ok {
		return nil, fmt.Errorf("rule %s: CEL returned %T, expected bool or list", rule.ID, native)
	}
	findings := make([]sdk.Finding, 0, len(entries))
	for index, entry := range entries {
		violation, ok := entry.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("rule %s: violation %d must be an object", rule.ID, index)
		}
		message := stringValue(violation["message"], spec.Message)
		path := stringValue(violation["path"], "")
		key := stringValue(violation["key"], fmt.Sprintf("cel:%d", index))
		line := intValue(violation["line"])
		column := intValue(violation["column"])
		findings = append(findings, finding(rule, message, path, key, line, column))
	}
	return findings, nil
}

func compileCEL(spec celSpec) (*cel.Env, cel.Program, error) {
	environment, err := cel.NewEnv(
		cel.Variable("repo", cel.DynType), cel.Variable("git", cel.DynType),
		cel.Variable("files", cel.ListType(cel.DynType)), cel.Variable("documents", cel.ListType(cel.DynType)),
		cel.Variable("items", cel.ListType(cel.DynType)), cel.Variable("params", cel.DynType),
		cel.Variable("now", cel.TimestampType),
	)
	if err != nil {
		return nil, nil, err
	}
	ast, issues := environment.Compile(spec.Expression)
	if issues != nil && issues.Err() != nil {
		return nil, nil, fmt.Errorf("CEL compile: %w", issues.Err())
	}
	limit := spec.CostLimit
	if limit == 0 {
		limit = 100_000
	}
	if limit > 1_000_000 {
		return nil, nil, fmt.Errorf("CEL costLimit may not exceed 1000000")
	}
	program, err := environment.Program(ast, cel.CostLimit(limit))
	if err != nil {
		return nil, nil, err
	}
	return environment, program, nil
}

func stringValue(value any, fallback string) string {
	if result, ok := value.(string); ok && strings.TrimSpace(result) != "" {
		return result
	}
	return fallback
}

func intValue(value any) int {
	switch current := value.(type) {
	case int:
		return current
	case int64:
		return int(current)
	case uint64:
		return int(current)
	case float64:
		return int(current)
	default:
		return 0
	}
}

func filepathBase(path string) string {
	path = strings.TrimRight(strings.ReplaceAll(path, "\\", "/"), "/")
	if index := strings.LastIndex(path, "/"); index >= 0 {
		return path[index+1:]
	}
	return path
}
