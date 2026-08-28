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
	if strings.TrimSpace(spec.RequiredProducer) == "" {
		return fmt.Errorf("rule %s: requiredProducer is required", rule.ID)
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
	contractDocs, hit, err := document.ParseCached(contractFile, "auto")
	if err != nil {
		return nil, err
	}
	if hit && input.Metrics != nil {
		input.Metrics.ParseCacheHits++
	}
	if len(contractDocs) != 1 {
		return nil, fmt.Errorf("%s: OpenAPI contract must contain exactly one document", contractFile.Path)
	}
	contract, ok := contractDocs[0].Data.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s: OpenAPI contract must be an object", contractFile.Path)
	}
	if version, _ := contract["openapi"].(string); !strings.HasPrefix(version, "3.") {
		return nil, fmt.Errorf("%s: OpenAPI 3.x contract is required", contractFile.Path)
	}
	operations, err := openAPIOperations(contract)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", contractFile.Path, err)
	}
	evidenceFile, err := input.Repository.Read(spec.ConsumptionPath)
	if err != nil {
		return []sdk.Finding{finding(rule, "API consumption evidence is missing", spec.ConsumptionPath, "evidence:missing", 1, 1)}, nil
	}
	evidenceDocs, hit, err := document.ParseCached(evidenceFile, "json")
	if err != nil {
		return nil, err
	}
	if hit && input.Metrics != nil {
		input.Metrics.ParseCacheHits++
	}
	evidenceRoot, ok := evidenceDocs[0].Data.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s: consumption evidence must be an object", evidenceFile.Path)
	}
	for key := range evidenceRoot {
		if key != "version" && key != "contractDigest" && key != "producer" && key != "operations" {
			return nil, fmt.Errorf("%s: unknown consumption evidence field %s", evidenceFile.Path, key)
		}
	}
	if version, ok := evidenceRoot["version"].(int64); !ok || version != 1 {
		return nil, fmt.Errorf("%s: consumption evidence version must be 1", evidenceFile.Path)
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
	consumed := map[string]bool{}
	values, ok := evidenceRoot["operations"].([]any)
	if !ok {
		return nil, fmt.Errorf("%s: operations must be an array", evidenceFile.Path)
	}
	for index, raw := range values {
		operation, ok := raw.(string)
		if !ok || !canonicalOperation(operation) {
			return nil, fmt.Errorf("%s: operation %d must be a canonical string", evidenceFile.Path, index)
		}
		if consumed[operation] {
			return nil, fmt.Errorf("%s: operation %s is duplicated", evidenceFile.Path, operation)
		}
		consumed[operation] = true
		if !spec.AllowUndeclaredEvidence && !operations[operation] {
			findings = append(findings, finding(rule, message+": evidence references undeclared operation "+operation, evidenceFile.Path, "undeclared:"+operation, 1, 1))
		}
	}
	if spec.RequireAllOperations {
		keys := make([]string, 0, len(operations))
		for operation := range operations {
			keys = append(keys, operation)
		}
		sort.Strings(keys)
		for _, operation := range keys {
			if !consumed[operation] {
				findings = append(findings, finding(rule, message+": operation has no consumption evidence "+operation, contractFile.Path, "unconsumed:"+operation, 1, 1))
			}
		}
	}
	return findings, nil
}

func openAPIOperations(contract map[string]any) (map[string]bool, error) {
	result := map[string]bool{}
	info, infoOK := contract["info"].(map[string]any)
	paths, pathsOK := contract["paths"].(map[string]any)
	if !infoOK || stringValue(info["title"], "") == "" || stringValue(info["version"], "") == "" || !pathsOK {
		return nil, fmt.Errorf("OpenAPI info.title, info.version, and paths are required")
	}
	methods := map[string]bool{"get": true, "put": true, "post": true, "delete": true, "options": true, "head": true, "patch": true, "trace": true}
	for route, raw := range paths {
		if !strings.HasPrefix(route, "/") {
			return nil, fmt.Errorf("OpenAPI path %s must start with /", route)
		}
		item, ok := raw.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("OpenAPI path %s must be an object", route)
		}
		for method, operation := range item {
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
