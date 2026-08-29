package rules

import (
	"context"
	"fmt"
	"math"
	"reflect"
	"strconv"
	"strings"
	"sync"

	"cel.dev/cel-go/cel"
	"github.com/openhoo/hoolicy/internal/document"
	"github.com/openhoo/hoolicy/sdk"
)

const celProgramCacheLimit = 128

type CEL struct {
	compiler *celCompiler
}

type celCompiler struct {
	environment *cel.Env
	mu          sync.Mutex
	programs    map[celProgramKey]cel.Program
	order       []celProgramKey
}

type celProgramKey struct {
	expression string
	costLimit  uint64
}

type celSpec struct {
	Format     string `yaml:"format,omitempty"`
	Expression string `yaml:"expression"`
	Message    string `yaml:"message"`
	CostLimit  uint64 `yaml:"costLimit,omitempty"`
}

func (kind CEL) Validate(rule sdk.Rule) error {
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
	_, err := kind.compile(spec)
	return err
}

func (kind CEL) Evaluate(_ context.Context, input sdk.EvalContext, rule sdk.Rule) ([]sdk.Finding, error) {
	var spec celSpec
	if err := decodeSpec(rule, &spec); err != nil {
		return nil, err
	}
	program, err := kind.compile(spec)
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
		parsed, hit, parseErr := document.ParseCached(file, spec.Format)
		if parseErr != nil {
			return nil, parseErr
		}
		if hit && input.Metrics != nil {
			input.Metrics.ParseCacheHits++
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
	result, details, err := program.Eval(variables)
	if err != nil {
		return nil, fmt.Errorf("rule %s: CEL evaluation: %w", rule.ID, err)
	}
	if input.Metrics != nil && details != nil && details.ActualCost() != nil {
		input.Metrics.CELCost = *details.ActualCost()
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
		line, err := locationValue(violation["line"])
		if err != nil {
			return nil, fmt.Errorf("rule %s: violation %d line: %w", rule.ID, index, err)
		}
		column, err := locationValue(violation["column"])
		if err != nil {
			return nil, fmt.Errorf("rule %s: violation %d column: %w", rule.ID, index, err)
		}
		findings = append(findings, finding(rule, message, path, key, line, column))
	}
	return findings, nil
}

func newCEL() (CEL, error) {
	environment, err := cel.NewEnv(
		cel.Variable("repo", cel.DynType), cel.Variable("git", cel.DynType),
		cel.Variable("files", cel.ListType(cel.DynType)), cel.Variable("documents", cel.ListType(cel.DynType)),
		cel.Variable("items", cel.ListType(cel.DynType)), cel.Variable("params", cel.DynType),
		cel.Variable("now", cel.TimestampType),
	)
	if err != nil {
		return CEL{}, err
	}
	return CEL{compiler: &celCompiler{environment: environment, programs: make(map[celProgramKey]cel.Program)}}, nil
}

func (kind CEL) compile(spec celSpec) (cel.Program, error) {
	limit, err := celCostLimit(spec.CostLimit)
	if err != nil {
		return nil, err
	}
	if kind.compiler == nil {
		uncached, err := newCEL()
		if err != nil {
			return nil, err
		}
		return compileCEL(uncached.compiler.environment, spec.Expression, limit)
	}
	key := celProgramKey{expression: spec.Expression, costLimit: limit}
	kind.compiler.mu.Lock()
	defer kind.compiler.mu.Unlock()
	if program, ok := kind.compiler.programs[key]; ok {
		return program, nil
	}
	program, err := compileCEL(kind.compiler.environment, spec.Expression, limit)
	if err != nil {
		return nil, err
	}
	if len(kind.compiler.order) == celProgramCacheLimit {
		delete(kind.compiler.programs, kind.compiler.order[0])
		copy(kind.compiler.order, kind.compiler.order[1:])
		kind.compiler.order = kind.compiler.order[:celProgramCacheLimit-1]
	}
	kind.compiler.programs[key] = program
	kind.compiler.order = append(kind.compiler.order, key)
	return program, nil
}

func compileCEL(environment *cel.Env, expression string, limit uint64) (cel.Program, error) {
	ast, issues := environment.Compile(expression)
	if issues != nil && issues.Err() != nil {
		return nil, fmt.Errorf("CEL compile: %w", issues.Err())
	}
	program, err := environment.Program(ast, cel.CostLimit(limit))
	if err != nil {
		return nil, err
	}
	return program, nil
}

func celCostLimit(limit uint64) (uint64, error) {
	if limit == 0 {
		limit = 100_000
	}
	if limit > 1_000_000 {
		return 0, fmt.Errorf("CEL costLimit may not exceed 1000000")
	}
	return limit, nil
}

func stringValue(value any, fallback string) string {
	if result, ok := value.(string); ok && strings.TrimSpace(result) != "" {
		return result
	}
	return fallback
}

func locationValue(value any) (int, error) {
	if value == nil {
		return 0, nil
	}
	maximum := uint64(^uint(0) >> 1)
	switch current := value.(type) {
	case int:
		if current < 0 {
			return 0, fmt.Errorf("must be a non-negative integer")
		}
		return current, nil
	case int64:
		if current < 0 || uint64(current) > maximum {
			return 0, fmt.Errorf("must be a non-negative platform integer")
		}
		return int(current), nil
	case uint64:
		if current > maximum {
			return 0, fmt.Errorf("must fit a platform integer")
		}
		return int(current), nil
	case float64:
		upperBound := math.Ldexp(1, strconv.IntSize-1)
		if math.IsNaN(current) || math.IsInf(current, 0) || current < 0 || current >= upperBound || math.Trunc(current) != current {
			return 0, fmt.Errorf("must be a non-negative platform integer")
		}
		return int(current), nil
	default:
		return 0, fmt.Errorf("must be an integer, got %T", value)
	}
}

func filepathBase(path string) string {
	path = strings.TrimRight(strings.ReplaceAll(path, "\\", "/"), "/")
	if index := strings.LastIndex(path, "/"); index >= 0 {
		return path[index+1:]
	}
	return path
}
