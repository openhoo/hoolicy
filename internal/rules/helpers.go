package rules

import (
	"bytes"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/openhoo/hoolicy/internal/repository"
	"github.com/openhoo/hoolicy/sdk"
	"go.yaml.in/yaml/v3"
)

func decodeSpec(rule sdk.Rule, target any) error {
	data, err := yaml.Marshal(rule.Spec)
	if err != nil {
		return err
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("rule %s spec: %w", rule.ID, err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return fmt.Errorf("rule %s spec: exactly one document is required", rule.ID)
	}
	return nil
}

func requireFiles(rule sdk.Rule) error {
	if len(rule.Files) == 0 {
		return fmt.Errorf("rule %s requires at least one file pattern", rule.ID)
	}
	if _, err := repository.Matches("", rule.Files); err != nil {
		return fmt.Errorf("rule %s files: %w", rule.ID, err)
	}
	if _, err := repository.Matches("", rule.Exclude); err != nil {
		return fmt.Errorf("rule %s exclude: %w", rule.ID, err)
	}
	return nil
}

func safeRelativeRulePath(path string) bool {
	if strings.TrimSpace(path) == "" || filepath.IsAbs(path) {
		return false
	}
	clean := filepath.Clean(filepath.FromSlash(path))
	return clean != "." && clean != ".." && !strings.HasPrefix(clean, ".."+string(filepath.Separator))
}

func finding(rule sdk.Rule, message, path, key string, line, column int) sdk.Finding {
	message = strings.TrimSpace(message)
	if utf8.RuneCountInString(message) > 500 {
		runes := []rune(message)
		message = string(runes[:497]) + "..."
	}
	return sdk.Finding{
		RuleID: rule.ID, Title: rule.Title, Message: message,
		Remediation: rule.Remediation, Severity: rule.Severity,
		Location: sdk.Location{Path: path, Line: line, Column: column},
		Key:      key, Controls: append([]sdk.Control(nil), rule.Controls...), Pack: rule.Pack,
	}
}

func lineColumn(data []byte, offset int) (int, int) {
	if offset < 0 {
		return 1, 1
	}
	if offset > len(data) {
		offset = len(data)
	}
	line := 1
	lastLine := -1
	for i, value := range data[:offset] {
		if value == '\n' {
			line++
			lastLine = i
		}
	}
	return line, utf8.RuneCount(data[lastLine+1:offset]) + 1
}

func compilePatterns(patterns []string) ([]*regexp.Regexp, error) {
	compiled := make([]*regexp.Regexp, 0, len(patterns))
	for _, pattern := range patterns {
		expression, err := regexp.Compile(pattern)
		if err != nil {
			return nil, err
		}
		compiled = append(compiled, expression)
	}
	return compiled, nil
}
