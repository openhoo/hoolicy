package rules

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/openhoo/hoolicy/internal/document"
	"github.com/openhoo/hoolicy/sdk"
)

type I18nParity struct{}

type i18nSpec struct {
	Manifest         string `yaml:"manifest"`
	CodesPointer     string `yaml:"codesPointer"`
	LocalesDirectory string `yaml:"localesDirectory"`
	Filename         string `yaml:"filename,omitempty"`
	Message          string `yaml:"message"`
}

func (I18nParity) Validate(rule sdk.Rule) error {
	var spec i18nSpec
	if err := decodeSpec(rule, &spec); err != nil {
		return err
	}
	if spec.Manifest == "" || spec.LocalesDirectory == "" {
		return fmt.Errorf("rule %s: i18n.parity requires manifest and localesDirectory", rule.ID)
	}
	if !safeRelativeRulePath(spec.Manifest) || !safeRelativeRulePath(spec.LocalesDirectory) {
		return fmt.Errorf("rule %s: manifest and localesDirectory must stay within the repository", rule.ID)
	}
	if err := validateJSONPointer(spec.CodesPointer); err != nil {
		return fmt.Errorf("rule %s: codesPointer %w", rule.ID, err)
	}
	if spec.Filename != "" && (!safeRelativeRulePath(spec.Filename) || strings.ContainsAny(spec.Filename, "/\\")) {
		return fmt.Errorf("rule %s: filename must be one safe path segment", rule.ID)
	}
	return nil
}

func (I18nParity) Evaluate(_ context.Context, input sdk.EvalContext, rule sdk.Rule) ([]sdk.Finding, error) {
	var spec i18nSpec
	if err := decodeSpec(rule, &spec); err != nil {
		return nil, err
	}
	if spec.Filename == "" {
		spec.Filename = "translation.json"
	}
	manifest, err := input.Repository.Read(spec.Manifest)
	if err != nil {
		return nil, err
	}
	value, err := readPointer(manifest, spec.CodesPointer, input.Metrics)
	if err != nil {
		return nil, err
	}
	languages, err := languageCodes(value)
	if err != nil {
		return nil, fmt.Errorf("rule %s: %w", rule.ID, err)
	}
	message := spec.Message
	if message == "" {
		message = "Translation catalogs must contain the same non-empty string keys"
	}
	catalogs := make(map[string]map[string]string)
	var findings []sdk.Finding
	allKeys := make(map[string]bool)
	for _, language := range languages {
		path := filepath.ToSlash(filepath.Join(spec.LocalesDirectory, language, spec.Filename))
		file, readErr := input.Repository.Read(path)
		if readErr != nil {
			findings = append(findings, finding(rule, message+": catalog is missing for "+language, path, language+":<catalog>", 1, 1))
			continue
		}
		documents, hit, parseErr := document.ParseCached(file, "json")
		if parseErr != nil {
			return nil, parseErr
		}
		if hit && input.Metrics != nil {
			input.Metrics.ParseCacheHits++
		}
		object, ok := documents[0].Data.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%s: translation catalog must be an object", path)
		}
		catalog := make(map[string]string)
		flattenCatalog("", object, catalog)
		catalogs[language] = catalog
		for key := range catalog {
			allKeys[key] = true
		}
	}
	keys := make([]string, 0, len(allKeys))
	for key := range allKeys {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, language := range languages {
		catalog, exists := catalogs[language]
		if !exists {
			continue
		}
		path := filepath.ToSlash(filepath.Join(spec.LocalesDirectory, language, spec.Filename))
		for _, key := range keys {
			if strings.TrimSpace(catalog[key]) == "" {
				findings = append(findings, finding(rule, fmt.Sprintf("%s: %s is missing or empty in %s", message, key, language), path, language+":"+key, 1, 1))
			}
		}
	}
	return findings, nil
}

func languageCodes(value any) ([]string, error) {
	list, ok := value.([]any)
	if !ok {
		return nil, fmt.Errorf("language manifest pointer must reference a list")
	}
	seen := map[string]bool{}
	var languages []string
	for _, entry := range list {
		var code string
		switch current := entry.(type) {
		case string:
			code = current
		case map[string]any:
			code, _ = current["code"].(string)
		}
		code = strings.TrimSpace(code)
		if code == "" {
			return nil, fmt.Errorf("language entry lacks code")
		}
		if code == "." || code == ".." || strings.ContainsAny(code, "/\\\x00") {
			return nil, fmt.Errorf("language code %q must be one safe path segment", code)
		}
		if seen[code] {
			return nil, fmt.Errorf("duplicate language code %s", code)
		}
		seen[code] = true
		languages = append(languages, code)
	}
	sort.Strings(languages)
	return languages, nil
}

func flattenCatalog(prefix string, value map[string]any, target map[string]string) {
	for key, entry := range value {
		path := key
		if prefix != "" {
			path = prefix + "." + key
		}
		switch current := entry.(type) {
		case map[string]any:
			flattenCatalog(path, current, target)
		case string:
			target[path] = current
		default:
			target[path] = ""
		}
	}
}
