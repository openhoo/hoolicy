package rules

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"regexp"
	"strconv"
	"strings"

	"github.com/openhoo/hoolicy/internal/document"
	"github.com/openhoo/hoolicy/sdk"
)

// StructuredFields applies declarative constraints to individual configuration fields.
type StructuredFields struct{}

type structuredFieldsSpec struct {
	Format       string            `yaml:"format,omitempty"`
	Fields       []structuredField `yaml:"fields"`
	AllowNoFiles bool              `yaml:"allowNoFiles,omitempty"`
	Message      string            `yaml:"message,omitempty"`
}

type structuredField struct {
	Pointer       *string  `yaml:"pointer"`
	Required      bool     `yaml:"required,omitempty"`
	Forbidden     bool     `yaml:"forbidden,omitempty"`
	Type          string   `yaml:"type,omitempty"`
	AllowedValues []any    `yaml:"allowedValues,omitempty"`
	Pattern       string   `yaml:"pattern,omitempty"`
	Minimum       *float64 `yaml:"minimum,omitempty"`
	Maximum       *float64 `yaml:"maximum,omitempty"`
	MinItems      *int     `yaml:"minItems,omitempty"`
	MaxItems      *int     `yaml:"maxItems,omitempty"`
	UniqueItems   bool     `yaml:"uniqueItems,omitempty"`
	RequiredItems []any    `yaml:"requiredItems,omitempty"`
}

func (StructuredFields) Validate(rule sdk.Rule) error {
	if err := requireFiles(rule); err != nil {
		return err
	}
	var spec structuredFieldsSpec
	if err := decodeSpec(rule, &spec); err != nil {
		return err
	}
	switch spec.Format {
	case "", "auto", "json", "yaml", "yml", "toml":
	default:
		return fmt.Errorf("rule %s: unsupported structured.fields format %q", rule.ID, spec.Format)
	}
	if len(spec.Fields) == 0 || len(spec.Fields) > 256 {
		return fmt.Errorf("rule %s: fields must contain between 1 and 256 constraints", rule.ID)
	}
	seen := map[string]bool{}
	for _, field := range spec.Fields {
		if field.Pointer == nil {
			return fmt.Errorf("rule %s: each field requires an explicit pointer (empty string selects the root)", rule.ID)
		}
		if err := validateJSONPointer(*field.Pointer); err != nil {
			return fmt.Errorf("rule %s: %w", rule.ID, err)
		}
		if seen[*field.Pointer] {
			return fmt.Errorf("rule %s: duplicate field pointer %q", rule.ID, *field.Pointer)
		}
		seen[*field.Pointer] = true
		switch field.Type {
		case "", "string", "number", "integer", "boolean", "array", "object", "null":
		default:
			return fmt.Errorf("rule %s: unsupported field type %q", rule.ID, field.Type)
		}
		checks := field.Type != "" || field.AllowedValues != nil || field.Pattern != "" || field.Minimum != nil || field.Maximum != nil || field.MinItems != nil || field.MaxItems != nil || field.UniqueItems || field.RequiredItems != nil
		if field.Forbidden && (field.Required || checks) {
			return fmt.Errorf("rule %s: forbidden field %q cannot have other constraints", rule.ID, *field.Pointer)
		}
		if !field.Required && !field.Forbidden && !checks {
			return fmt.Errorf("rule %s: field %q has no constraints", rule.ID, *field.Pointer)
		}
		if field.AllowedValues != nil && (len(field.AllowedValues) == 0 || len(field.AllowedValues) > 256) || field.RequiredItems != nil && (len(field.RequiredItems) == 0 || len(field.RequiredItems) > 256) {
			return fmt.Errorf("rule %s: value lists must contain between 1 and 256 values", rule.ID)
		}
		if field.Pattern != "" {
			if len(field.Pattern) > 4096 {
				return fmt.Errorf("rule %s: pattern exceeds 4096 bytes", rule.ID)
			}
			if _, err := regexp.Compile(field.Pattern); err != nil {
				return fmt.Errorf("rule %s: invalid pattern: %w", rule.ID, err)
			}
			if field.Type != "" && field.Type != "string" {
				return fmt.Errorf("rule %s: pattern requires string type", rule.ID)
			}
		}
		if field.Minimum != nil || field.Maximum != nil {
			if field.Type != "" && field.Type != "number" && field.Type != "integer" {
				return fmt.Errorf("rule %s: numeric bounds require number or integer type", rule.ID)
			}
			for _, bound := range []*float64{field.Minimum, field.Maximum} {
				if bound != nil && (math.IsNaN(*bound) || math.IsInf(*bound, 0)) {
					return fmt.Errorf("rule %s: numeric bounds must be finite", rule.ID)
				}
			}
			if field.Minimum != nil && field.Maximum != nil && *field.Minimum > *field.Maximum {
				return fmt.Errorf("rule %s: minimum exceeds maximum", rule.ID)
			}
		}
		if field.MinItems != nil || field.MaxItems != nil || field.UniqueItems || field.RequiredItems != nil {
			if field.Type != "" && field.Type != "array" {
				return fmt.Errorf("rule %s: item constraints require array type", rule.ID)
			}
			if field.MinItems != nil && *field.MinItems < 0 || field.MaxItems != nil && *field.MaxItems < 0 {
				return fmt.Errorf("rule %s: item bounds must be non-negative", rule.ID)
			}
			if field.MinItems != nil && field.MaxItems != nil && *field.MinItems > *field.MaxItems {
				return fmt.Errorf("rule %s: minItems exceeds maxItems", rule.ID)
			}
		}
		for _, values := range [][]any{field.AllowedValues, field.RequiredItems} {
			for _, value := range values {
				if _, err := structuredCanonical(context.Background(), value, 0); err != nil {
					return fmt.Errorf("rule %s: values must be JSON-compatible: %w", rule.ID, err)
				}
			}
		}
	}
	return nil
}

func (kind StructuredFields) Evaluate(ctx context.Context, input sdk.EvalContext, rule sdk.Rule) ([]sdk.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := kind.Validate(rule); err != nil {
		return nil, err
	}
	var spec structuredFieldsSpec
	if err := decodeSpec(rule, &spec); err != nil {
		return nil, err
	}
	files, err := input.Repository.Match(rule.Files, rule.Exclude)
	if err != nil {
		return nil, err
	}
	if len(files) == 0 && !spec.AllowNoFiles {
		return []sdk.Finding{finding(rule, "No files matched the structured field policy", "", "no-files", 0, 0)}, nil
	}
	patterns := make(map[string]*regexp.Regexp)
	for _, field := range spec.Fields {
		if field.Pattern != "" {
			patterns[*field.Pointer] = regexp.MustCompile(field.Pattern)
		}
	}
	var findings []sdk.Finding
	for _, file := range files {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		parsed, hit, err := document.ParseCached(file, spec.Format)
		if err != nil {
			return nil, err
		}
		if hit && input.Metrics != nil {
			input.Metrics.ParseCacheHits++
		}
		if len(parsed) == 0 {
			findings = append(findings, finding(rule, "Configuration file contains no documents", file.Path, "no-documents", 1, 1))
		}
		for _, item := range parsed {
			for _, field := range spec.Fields {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
				value, exists := structuredPointer(item.Data, *field.Pointer)
				reasons, err := structuredViolations(ctx, value, exists, field, patterns[*field.Pointer])
				if err != nil {
					return nil, err
				}
				for _, reason := range reasons {
					message := fmt.Sprintf("Field %q %s", *field.Pointer, reason)
					if spec.Message != "" {
						message = spec.Message + ": " + message
					}
					findings = append(findings, finding(rule, message, file.Path, fmt.Sprintf("document:%d:%s:%s", item.Index, *field.Pointer, reason), item.Line, item.Column))
				}
			}
		}
	}
	return findings, nil
}

func structuredPointer(value any, pointer string) (any, bool) {
	if pointer == "" {
		return value, true
	}
	for _, token := range strings.Split(pointer[1:], "/") {
		token = strings.ReplaceAll(strings.ReplaceAll(token, "~1", "/"), "~0", "~")
		switch current := value.(type) {
		case map[string]any:
			var exists bool
			value, exists = current[token]
			if !exists {
				return nil, false
			}
		case []any:
			if token == "" || len(token) > 1 && token[0] == '0' {
				return nil, false
			}
			for _, digit := range token {
				if digit < '0' || digit > '9' {
					return nil, false
				}
			}
			index, err := strconv.Atoi(token)
			if err != nil || index >= len(current) {
				return nil, false
			}
			value = current[index]
		default:
			return nil, false
		}
	}
	return value, true
}

func structuredViolations(ctx context.Context, value any, exists bool, field structuredField, pattern *regexp.Regexp) ([]string, error) {
	if !exists {
		if field.Required {
			return []string{"is required"}, nil
		}
		return nil, nil
	}
	if field.Forbidden {
		return []string{"is forbidden"}, nil
	}
	if field.Type == "number" || field.Type == "integer" || field.Minimum != nil || field.Maximum != nil {
		if _, _, err := structuredCheckedNumber(value); err != nil {
			return nil, err
		}
	}
	var reasons []string
	if field.Type != "" && !structuredType(value, field.Type) {
		reasons = append(reasons, "must have type "+field.Type)
	}
	if field.AllowedValues != nil {
		contains, err := structuredContains(ctx, field.AllowedValues, value)
		if err != nil {
			return nil, err
		}
		if !contains {
			reasons = append(reasons, "must match an allowed value")
		}
	}
	if pattern != nil {
		text, ok := value.(string)
		if !ok || !pattern.MatchString(text) {
			reasons = append(reasons, "must match the required string pattern")
		}
	}
	if field.Minimum != nil || field.Maximum != nil {
		number, ok := structuredNumber(value)
		if !ok {
			reasons = append(reasons, "must be a number for numeric bounds")
		} else {
			if field.Minimum != nil {
				bound, _ := structuredNumber(*field.Minimum)
				if number.Cmp(bound) < 0 {
					reasons = append(reasons, "is below the minimum")
				}
			}
			if field.Maximum != nil {
				bound, _ := structuredNumber(*field.Maximum)
				if number.Cmp(bound) > 0 {
					reasons = append(reasons, "exceeds the maximum")
				}
			}
		}
	}
	if field.MinItems != nil || field.MaxItems != nil || field.UniqueItems || field.RequiredItems != nil {
		items, ok := value.([]any)
		if !ok {
			reasons = append(reasons, "must be an array for item constraints")
		} else {
			if field.MinItems != nil && len(items) < *field.MinItems {
				reasons = append(reasons, "has fewer than minItems")
			}
			if field.MaxItems != nil && len(items) > *field.MaxItems {
				reasons = append(reasons, "has more than maxItems")
			}

			if field.UniqueItems || field.RequiredItems != nil {
				if len(items) > 100000 {
					return nil, fmt.Errorf("structured.fields array comparison limit exceeded (100000 items)")
				}
				seen := make(map[string]bool, len(items))
				duplicate := false
				for _, item := range items {
					if err := ctx.Err(); err != nil {
						return nil, err
					}
					canonical, err := structuredCanonical(ctx, item, 0)
					if err != nil {
						return nil, fmt.Errorf("structured.fields comparison: %w", err)
					}
					data, err := json.Marshal(canonical)
					if err != nil {
						return nil, err
					}
					key := string(data)
					if seen[key] {
						duplicate = true
					}
					seen[key] = true
				}
				if field.UniqueItems && duplicate {
					reasons = append(reasons, "must contain unique items")
				}
				for _, required := range field.RequiredItems {
					if err := ctx.Err(); err != nil {
						return nil, err
					}
					canonical, err := structuredCanonical(ctx, required, 0)
					if err != nil {
						return nil, err
					}
					data, err := json.Marshal(canonical)
					if err != nil {
						return nil, err
					}
					if !seen[string(data)] {
						reasons = append(reasons, "is missing a required item")
						break
					}
				}
			}
		}
	}
	return reasons, nil
}

func structuredContains(ctx context.Context, values []any, value any) (bool, error) {
	normalized, err := structuredCanonical(ctx, value, 0)
	if err != nil {
		return false, err
	}
	for _, candidate := range values {
		other, err := structuredCanonical(ctx, candidate, 0)
		if err != nil {
			return false, err
		}
		equal, err := manifestValuesEqual(other, normalized)
		if err != nil {
			return false, err
		}
		if equal {
			return true, nil
		}
	}
	return false, nil
}

// Tag every container and number so a user's ordinary array or object cannot
// collide with the canonical numeric representation used for comparison.
func structuredCanonical(ctx context.Context, value any, depth int) (any, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if depth > 128 {
		return nil, fmt.Errorf("value nesting exceeds 128 levels")
	}
	switch current := value.(type) {
	case map[string]any:
		result := make(map[string]any, len(current))
		for key, item := range current {
			normalized, err := structuredCanonical(ctx, item, depth+1)
			if err != nil {
				return nil, err
			}
			result[key] = normalized
		}
		return []any{"object", result}, nil
	case []any:
		if len(current) > 100000 {
			return nil, fmt.Errorf("structured.fields array comparison limit exceeded (100000 items)")
		}
		result := make([]any, len(current))
		for index, item := range current {
			normalized, err := structuredCanonical(ctx, item, depth+1)
			if err != nil {
				return nil, err
			}
			result[index] = normalized
		}
		return []any{"array", result}, nil
	case string, bool, nil:
		return value, nil
	default:
		number, ok := structuredNumber(value)
		if !ok {
			return nil, fmt.Errorf("value must be a finite JSON-compatible number within comparison limits")
		}
		return []any{"number", number.RatString()}, nil
	}
}

func structuredType(value any, kind string) bool {
	switch kind {
	case "null":
		return value == nil
	case "string":
		_, ok := value.(string)
		return ok
	case "boolean":
		_, ok := value.(bool)
		return ok
	case "object":
		_, ok := value.(map[string]any)
		return ok
	case "array":
		_, ok := value.([]any)
		return ok
	case "number", "integer":
		number, ok := structuredNumber(value)
		return ok && (kind == "number" || number.IsInt())
	}
	return false
}

// Rational comparisons avoid silently rounding large JSON integers to float64.
func structuredNumber(value any) (*big.Rat, bool) {
	number, ok, _ := structuredCheckedNumber(value)
	return number, ok
}

// Wrong types are policy violations, while excessive numeric precision or
// exponents are resource-budget errors and must not become waivable findings.
func structuredCheckedNumber(value any) (*big.Rat, bool, error) {
	switch value.(type) {
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float32, float64, json.Number:
	default:
		return nil, false, nil
	}
	data, err := json.Marshal(value)
	if err != nil {
		return nil, false, fmt.Errorf("structured.fields numeric comparison: %w", err)
	}
	text := string(data)
	if len(text) > 4096 {
		return nil, false, fmt.Errorf("structured.fields numeric comparison limit exceeded (4096 bytes)")
	}
	if index := strings.IndexAny(text, "eE"); index >= 0 {
		exponent, err := strconv.Atoi(text[index+1:])
		if err != nil || exponent < -4096 || exponent > 4096 {
			return nil, false, fmt.Errorf("structured.fields numeric exponent comparison limit exceeded (4096)")
		}
	}
	number, ok := new(big.Rat).SetString(text)
	if !ok {
		return nil, false, fmt.Errorf("structured.fields number cannot be compared")
	}
	return number, true, nil
}
