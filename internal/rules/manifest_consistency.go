package rules

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
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
	authoritative, err := readPointer(authoritativeFile, spec.Authoritative.Pointer, input.Metrics)
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
		value, pointerErr := readPointer(file, target.Pointer, input.Metrics)
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

func readPointer(file sdk.File, pointer string, metrics *sdk.EvaluationMetrics) (any, error) {
	documents, hit, err := document.ParseCached(file, "auto")
	if err != nil {
		return nil, err
	}
	if hit && metrics != nil {
		metrics.ParseCacheHits++
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
	if err := validateJSONPointer(pointer); err != nil {
		return sdk.Edit{}, err
	}
	for _, value := range []any{oldValue, newValue} {
		switch value.(type) {
		case map[string]any, []any:
			return sdk.Edit{}, fmt.Errorf("safe automatic edit requires scalar values")
		}
	}
	// Validate the complete document, including duplicate keys, before locating
	// the exact pointer. Text searches can confuse sibling keys, escaped strings,
	// or a number such as 1 with the prefix of 10.
	if _, _, err := document.ParseCached(file, "json"); err != nil {
		return sdk.Edit{}, err
	}
	data := file.Data
	prefix := 0
	if bytes.HasPrefix(data, []byte{0xef, 0xbb, 0xbf}) {
		data = data[3:]
		prefix = 3
	}
	var tokens []string
	if pointer != "" {
		for _, token := range strings.Split(pointer[1:], "/") {
			tokens = append(tokens, strings.ReplaceAll(strings.ReplaceAll(token, "~1", "/"), "~0", "~"))
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	start, end, err := jsonPointerSpan(decoder, tokens)
	if err != nil {
		return sdk.Edit{}, err
	}
	current, err := document.Parse(sdk.File{Path: file.Path, Data: data[start:end]}, "json")
	if err != nil {
		return sdk.Edit{}, err
	}
	equal, err := manifestValuesEqual(current[0].Data, oldValue)
	if err != nil {
		return sdk.Edit{}, err
	}
	if !equal {
		return sdk.Edit{}, fmt.Errorf("target value changed")
	}
	newJSON, err := json.Marshal(newValue)
	if err != nil {
		return sdk.Edit{}, err
	}
	return sdk.Edit{Path: file.Path, ExpectedSHA256: file.SHA256(), Start: start + prefix, End: end + prefix, Replacement: newJSON, Description: "Set " + pointer}, nil
}

// jsonPointerSpan follows object keys using the decoder's byte offsets. Array
// pointers remain unsupported, matching readPointer's public rule contract.
func jsonPointerSpan(decoder *json.Decoder, tokens []string) (int, int, error) {
	if len(tokens) == 0 {
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			return 0, 0, err
		}
		end := int(decoder.InputOffset())
		return end - len(raw), end, nil
	}
	token, err := decoder.Token()
	if err != nil {
		return 0, 0, err
	}
	if token != json.Delim('{') {
		return 0, 0, fmt.Errorf("pointer must traverse objects")
	}
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return 0, 0, err
		}
		if token == tokens[0] {
			return jsonPointerSpan(decoder, tokens[1:])
		}
		var skipped json.RawMessage
		if err := decoder.Decode(&skipped); err != nil {
			return 0, 0, err
		}
	}
	return 0, 0, fmt.Errorf("pointer does not exist")
}
