package rules

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/openhoo/hoolicy/internal/document"
	"github.com/openhoo/hoolicy/sdk"
)

type ManifestConsistency struct{}

type manifestConsistencySpec struct {
	Authoritative manifestValue   `yaml:"authoritative"`
	Targets       []manifestValue `yaml:"targets"`
	Message       string          `yaml:"message"`
}

type manifestValue struct {
	Path    string `yaml:"path"`
	Pointer string `yaml:"pointer"`
}

func (ManifestConsistency) Validate(rule sdk.Rule) error {
	var spec manifestConsistencySpec
	if err := decodeSpec(rule, &spec); err != nil {
		return err
	}
	if spec.Authoritative.Path == "" || len(spec.Targets) == 0 {
		return fmt.Errorf("rule %s: manifest.consistency requires an authoritative path and targets", rule.ID)
	}
	seen := make(map[string]bool, len(spec.Targets))
	for index, value := range append([]manifestValue{spec.Authoritative}, spec.Targets...) {
		if !safeRelativeRulePath(value.Path) {
			return fmt.Errorf("rule %s: manifest path %q must stay within the repository", rule.ID, value.Path)
		}
		if err := validateJSONPointer(value.Pointer); err != nil {
			return fmt.Errorf("rule %s: %w", rule.ID, err)
		}
		key := value.Path + "\x00" + value.Pointer
		if index > 0 && seen[key] {
			return fmt.Errorf("rule %s: duplicate target %s%s", rule.ID, value.Path, value.Pointer)
		}
		seen[key] = true
	}
	return nil
}

func (ManifestConsistency) Evaluate(_ context.Context, input sdk.EvalContext, rule sdk.Rule) ([]sdk.Finding, error) {
	var spec manifestConsistencySpec
	if err := decodeSpec(rule, &spec); err != nil {
		return nil, err
	}
	authoritativeFile, err := input.Repository.Read(spec.Authoritative.Path)
	if err != nil {
		return nil, err
	}
	authoritative, err := readPointer(authoritativeFile, spec.Authoritative.Pointer)
	if err != nil {
		return nil, fmt.Errorf("rule %s authoritative value: %w", rule.ID, err)
	}
	message := spec.Message
	if message == "" {
		message = "Manifest values must match the authoritative value"
	}
	var findings []sdk.Finding
	for _, target := range spec.Targets {
		file, readErr := input.Repository.Read(target.Path)
		if readErr != nil {
			return nil, readErr
		}
		value, pointerErr := readPointer(file, target.Pointer)
		if pointerErr != nil {
			return nil, fmt.Errorf("rule %s target %s: %w", rule.ID, target.Path, pointerErr)
		}
		equal, compareErr := manifestValuesEqual(value, authoritative)
		if compareErr != nil {
			return nil, fmt.Errorf("rule %s compare %s: %w", rule.ID, target.Path, compareErr)
		}
		if equal {
			continue
		}
		result := finding(rule, fmt.Sprintf("%s: %s%s is %v, expected %v", message, target.Path, target.Pointer, value, authoritative), target.Path, target.Pointer, 1, 1)
		if edit, editErr := scalarJSONEdit(file, target.Pointer, value, authoritative); editErr == nil {
			result.Fix = &sdk.Fix{Description: "Synchronize value from " + spec.Authoritative.Path + spec.Authoritative.Pointer, Edits: []sdk.Edit{edit}}
		}
		findings = append(findings, result)
	}
	return findings, nil
}

func manifestValuesEqual(left, right any) (bool, error) {
	leftJSON, err := json.Marshal(left)
	if err != nil {
		return false, err
	}
	rightJSON, err := json.Marshal(right)
	if err != nil {
		return false, err
	}
	return bytes.Equal(leftJSON, rightJSON), nil
}

func readPointer(file sdk.File, pointer string) (any, error) {
	documents, err := document.Parse(file, "auto")
	if err != nil {
		return nil, err
	}
	if len(documents) != 1 {
		return nil, fmt.Errorf("expected exactly one document")
	}
	current := documents[0].Data
	if pointer == "" {
		return current, nil
	}
	for _, token := range strings.Split(strings.TrimPrefix(pointer, "/"), "/") {
		token = strings.ReplaceAll(strings.ReplaceAll(token, "~1", "/"), "~0", "~")
		switch value := current.(type) {
		case map[string]any:
			var exists bool
			current, exists = value[token]
			if !exists {
				return nil, fmt.Errorf("pointer %s does not exist", pointer)
			}
		case []any:
			return nil, fmt.Errorf("array pointers are not supported in manifest.consistency")
		default:
			return nil, fmt.Errorf("pointer %s traverses a scalar", pointer)
		}
	}
	return current, nil
}

func scalarJSONEdit(file sdk.File, pointer string, oldValue, newValue any) (sdk.Edit, error) {
	if strings.ToLower(filepath.Ext(file.Path)) != ".json" {
		return sdk.Edit{}, fmt.Errorf("safe automatic edit is only available for JSON")
	}
	tokens := strings.Split(strings.TrimPrefix(pointer, "/"), "/")
	if len(tokens) == 0 {
		return sdk.Edit{}, fmt.Errorf("invalid pointer")
	}
	key := strings.ReplaceAll(strings.ReplaceAll(tokens[len(tokens)-1], "~1", "/"), "~0", "~")
	oldJSON, err := json.Marshal(oldValue)
	if err != nil {
		return sdk.Edit{}, err
	}
	newJSON, err := json.Marshal(newValue)
	if err != nil {
		return sdk.Edit{}, err
	}
	pattern := regexp.MustCompile(`(?m)("` + regexp.QuoteMeta(key) + `"\s*:\s*)` + regexp.QuoteMeta(string(oldJSON)))
	locations := pattern.FindAllSubmatchIndex(file.Data, -1)
	if len(locations) != 1 {
		return sdk.Edit{}, fmt.Errorf("target scalar is not uniquely editable")
	}
	start := locations[0][3]
	end := locations[0][1]
	if !bytes.Equal(file.Data[start:end], oldJSON) {
		return sdk.Edit{}, fmt.Errorf("target value changed")
	}
	return sdk.Edit{Path: file.Path, ExpectedSHA256: file.SHA256(), Start: start, End: end, Replacement: newJSON, Description: "Set " + pointer}, nil
}
