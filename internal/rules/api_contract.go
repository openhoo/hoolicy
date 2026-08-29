package rules

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/openhoo/hoolicy/internal/document"
	"github.com/openhoo/hoolicy/sdk"
)

type APIContract struct{}

type apiContractSpec struct {
	ContractPath            string `yaml:"contractPath"`
	ConsumptionPath         string `yaml:"consumptionPath"`
	RequiredProducer        string `yaml:"requiredProducer"`
	RequireAllOperations    bool   `yaml:"requireAllOperations,omitempty"`
	AllowUndeclaredEvidence bool   `yaml:"allowUndeclaredEvidence,omitempty"`
	Message                 string `yaml:"message,omitempty"`
}

func (APIContract) Validate(rule sdk.Rule) error {
	var spec apiContractSpec
	if err := decodeSpec(rule, &spec); err != nil {
		return err
	}
	if !safeRelativeRulePath(spec.ContractPath) || !safeRelativeRulePath(spec.ConsumptionPath) {
		return fmt.Errorf("rule %s: contractPath and consumptionPath must stay within the repository", rule.ID)
	}
	if strings.TrimSpace(spec.RequiredProducer) == "" || strings.TrimSpace(spec.RequiredProducer) != spec.RequiredProducer || strings.ContainsAny(spec.RequiredProducer, "\x00\r\n") {
		return fmt.Errorf("rule %s: requiredProducer must be a non-empty single-line exact value", rule.ID)
	}
	return nil
}

func (APIContract) Evaluate(_ context.Context, input sdk.EvalContext, rule sdk.Rule) ([]sdk.Finding, error) {
	var spec apiContractSpec
	if err := decodeSpec(rule, &spec); err != nil {
		return nil, err
	}
	contractFile, err := input.Repository.Read(spec.ContractPath)
	if err != nil {
		return []sdk.Finding{finding(rule, "API contract is missing", spec.ContractPath, "contract:missing", 1, 1)}, nil
	}
	operations, err := contractOperations(contractFile, input.Metrics)
	if err != nil {
		return nil, err
	}
	evidenceFile, err := input.Repository.Read(spec.ConsumptionPath)
	if err != nil {
		return []sdk.Finding{finding(rule, "API consumption evidence is missing", spec.ConsumptionPath, "evidence:missing", 1, 1)}, nil
	}
	evidenceRoot, err := consumptionEvidence(evidenceFile, input.Metrics)
	if err != nil {
		return nil, err
	}
	message := spec.Message
	if message == "" {
		message = "OpenAPI operation and declared generated-client consumption evidence disagree"
	}
	var findings []sdk.Finding
	expectedDigest := "sha256:" + contractFile.SHA256()
	digest, _ := evidenceRoot["contractDigest"].(string)
	if digest != expectedDigest {
		findings = append(findings, finding(rule, message+": contract digest does not match", evidenceFile.Path, "contract-digest", 1, 1))
	}
	producer, _ := evidenceRoot["producer"].(string)
	if producer != spec.RequiredProducer {
		findings = append(findings, finding(rule, message+": producer "+producer+" is not "+spec.RequiredProducer, evidenceFile.Path, "producer", 1, 1))
	}
	consumed, operationFindings, err := consumedOperations(rule, evidenceFile.Path, evidenceRoot, operations, spec.AllowUndeclaredEvidence, message)
	if err != nil {
		return nil, err
	}
	findings = append(findings, operationFindings...)
	if spec.RequireAllOperations {
		findings = append(findings, unconsumedOperationFindings(rule, contractFile.Path, operations, consumed, message)...)
	}
	return findings, nil
}

func contractOperations(file sdk.File, metrics *sdk.EvaluationMetrics) (map[string]bool, error) {
	documents, hit, err := document.ParseCached(file, "auto")
	if err != nil {
		return nil, err
	}
	if hit && metrics != nil {
		metrics.ParseCacheHits++
	}
	if len(documents) != 1 {
		return nil, fmt.Errorf("%s: OpenAPI contract must contain exactly one document", file.Path)
	}
	contract, ok := documents[0].Data.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s: OpenAPI contract must be an object", file.Path)
	}
	if version, _ := contract["openapi"].(string); !strings.HasPrefix(version, "3.") {
		return nil, fmt.Errorf("%s: OpenAPI 3.x contract is required", file.Path)
	}
	operations, err := openAPIOperations(contract)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", file.Path, err)
	}
	return operations, nil
}

func consumptionEvidence(file sdk.File, metrics *sdk.EvaluationMetrics) (map[string]any, error) {
	documents, hit, err := document.ParseCached(file, "json")
	if err != nil {
		return nil, err
	}
	if hit && metrics != nil {
		metrics.ParseCacheHits++
	}
	if len(documents) != 1 {
		return nil, fmt.Errorf("%s: consumption evidence must contain exactly one document", file.Path)
	}
	root, ok := documents[0].Data.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s: consumption evidence must be an object", file.Path)
	}
	for _, key := range sortedObjectKeys(root) {
		if key != "version" && key != "contractDigest" && key != "producer" && key != "operations" {
			return nil, fmt.Errorf("%s: unknown consumption evidence field %s", file.Path, key)
		}
	}
	if version, ok := root["version"].(int64); !ok || version != 1 {
		return nil, fmt.Errorf("%s: consumption evidence version must be 1", file.Path)
	}
	return root, nil
}

func consumedOperations(rule sdk.Rule, path string, evidence map[string]any, declared map[string]bool, allowUndeclared bool, message string) (map[string]bool, []sdk.Finding, error) {
	values, ok := evidence["operations"].([]any)
	if !ok {
		return nil, nil, fmt.Errorf("%s: operations must be an array", path)
	}
	consumed := make(map[string]bool, len(values))
	var findings []sdk.Finding
	for index, raw := range values {
		operation, ok := raw.(string)
		if !ok || !canonicalOperation(operation) {
			return nil, nil, fmt.Errorf("%s: operation %d must be a canonical string", path, index)
		}
		if consumed[operation] {
			return nil, nil, fmt.Errorf("%s: operation %s is duplicated", path, operation)
		}
		consumed[operation] = true
		if !allowUndeclared && !declared[operation] {
			findings = append(findings, finding(rule, message+": evidence references undeclared operation "+operation, path, "undeclared:"+operation, 1, 1))
		}
	}
	return consumed, findings, nil
}

func unconsumedOperationFindings(rule sdk.Rule, path string, declared, consumed map[string]bool, message string) []sdk.Finding {
	keys := make([]string, 0, len(declared))
	for operation := range declared {
		keys = append(keys, operation)
	}
	sort.Strings(keys)
	var findings []sdk.Finding
	for _, operation := range keys {
		if !consumed[operation] {
			findings = append(findings, finding(rule, message+": operation has no consumption evidence "+operation, path, "unconsumed:"+operation, 1, 1))
		}
	}
	return findings
}

func openAPIOperations(contract map[string]any) (map[string]bool, error) {
	result := map[string]bool{}
	info, infoOK := contract["info"].(map[string]any)
	paths, pathsOK := contract["paths"].(map[string]any)
	if !infoOK || stringValue(info["title"], "") == "" || stringValue(info["version"], "") == "" || !pathsOK {
		return nil, fmt.Errorf("OpenAPI info.title, info.version, and paths are required")
	}
	methods := map[string]bool{"get": true, "put": true, "post": true, "delete": true, "options": true, "head": true, "patch": true, "trace": true}
	for _, route := range sortedObjectKeys(paths) {
		raw := paths[route]
		if !strings.HasPrefix(route, "/") {
			return nil, fmt.Errorf("OpenAPI path %s must start with /", route)
		}
		item, ok := raw.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("OpenAPI path %s must be an object", route)
		}
		for _, method := range sortedObjectKeys(item) {
			operation := item[method]
			lower := strings.ToLower(method)
			if methods[lower] {
				if _, ok := operation.(map[string]any); !ok {
					return nil, fmt.Errorf("OpenAPI operation %s %s must be an object", strings.ToUpper(lower), route)
				}
				result[strings.ToUpper(lower)+" "+route] = true
			}
		}
	}
	return result, nil
}

func sortedObjectKeys(object map[string]any) []string {
	keys := make([]string, 0, len(object))
	for key := range object {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func canonicalOperation(value string) bool {
	method, route, found := strings.Cut(value, " ")
	if !found || route == "" || !strings.HasPrefix(route, "/") || strings.ContainsAny(route, "\r\n\t ") {
		return false
	}
	switch method {
	case "GET", "PUT", "POST", "DELETE", "OPTIONS", "HEAD", "PATCH", "TRACE":
		return true
	}
	return false
}
