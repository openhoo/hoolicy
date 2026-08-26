package rules

import (
	"context"
	"fmt"

	"github.com/openhoo/hoolicy/sdk"
)

type Text struct{}

type textSpec struct {
	Require []string `yaml:"require,omitempty"`
	Forbid  []string `yaml:"forbid,omitempty"`
	Message string   `yaml:"message"`
}

func (Text) Validate(rule sdk.Rule) error {
	if err := requireFiles(rule); err != nil {
		return err
	}
	var spec textSpec
	if err := decodeSpec(rule, &spec); err != nil {
		return err
	}
	if len(spec.Require) == 0 && len(spec.Forbid) == 0 {
		return fmt.Errorf("rule %s: text rule needs require or forbid expressions", rule.ID)
	}
	if _, err := compilePatterns(append(append([]string(nil), spec.Require...), spec.Forbid...)); err != nil {
		return fmt.Errorf("rule %s: %w", rule.ID, err)
	}
	return nil
}

func (Text) Evaluate(_ context.Context, input sdk.EvalContext, rule sdk.Rule) ([]sdk.Finding, error) {
	var spec textSpec
	if err := decodeSpec(rule, &spec); err != nil {
		return nil, err
	}
	required, _ := compilePatterns(spec.Require)
	forbidden, _ := compilePatterns(spec.Forbid)
	files, err := input.Repository.Match(rule.Files, rule.Exclude)
	if err != nil {
		return nil, err
	}
	message := spec.Message
	if message == "" {
		message = "Text requirement did not pass"
	}
	var findings []sdk.Finding
	for _, file := range files {
		for index, expression := range required {
			if !expression.Match(file.Data) {
				findings = append(findings, finding(rule, message, file.Path, fmt.Sprintf("require:%d", index), 1, 1))
			}
		}
		for index, expression := range forbidden {
			for _, location := range expression.FindAllIndex(file.Data, -1) {
				line, column := lineColumn(file.Data, location[0])
				findings = append(findings, finding(rule, message, file.Path, fmt.Sprintf("forbid:%d", index), line, column))
			}
		}
	}
	return findings, nil
}
