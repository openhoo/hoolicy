package rules

import (
	"context"
	"fmt"

	"github.com/openhoo/hoolicy/sdk"
)

type Files struct{}

type filesSpec struct {
	Mode    string `yaml:"mode"`
	Minimum int    `yaml:"minimum,omitempty"`
	Maximum int    `yaml:"maximum,omitempty"`
	Message string `yaml:"message"`
	Create  *struct {
		Path    string `yaml:"path"`
		Content string `yaml:"content"`
	} `yaml:"create,omitempty"`
}

func (Files) Validate(rule sdk.Rule) error {
	if err := requireFiles(rule); err != nil {
		return err
	}
	var spec filesSpec
	if err := decodeSpec(rule, &spec); err != nil {
		return err
	}
	if spec.Mode != "require" && spec.Mode != "forbid" && spec.Mode != "count" {
		return fmt.Errorf("rule %s: files mode must be require, forbid, or count", rule.ID)
	}
	if spec.Mode == "count" && spec.Minimum == 0 && spec.Maximum == 0 {
		return fmt.Errorf("rule %s: count mode needs minimum or maximum", rule.ID)
	}
	if spec.Create != nil && (spec.Mode != "require" || spec.Create.Path == "") {
		return fmt.Errorf("rule %s: create fix requires require mode and path", rule.ID)
	}
	return nil
}

func (Files) Evaluate(_ context.Context, input sdk.EvalContext, rule sdk.Rule) ([]sdk.Finding, error) {
	var spec filesSpec
	if err := decodeSpec(rule, &spec); err != nil {
		return nil, err
	}
	matches, err := input.Repository.Match(rule.Files, rule.Exclude)
	if err != nil {
		return nil, err
	}
	message := spec.Message
	if message == "" {
		message = fmt.Sprintf("File policy %s did not pass", rule.ID)
	}
	switch spec.Mode {
	case "require":
		if len(matches) == 0 {
			result := finding(rule, message, "", "missing", 0, 0)
			if spec.Create != nil {
				result.Fix = &sdk.Fix{Description: "Create " + spec.Create.Path, Edits: []sdk.Edit{{
					Path: spec.Create.Path, ExpectedSHA256: "missing", Start: 0, End: 0,
					Replacement: []byte(spec.Create.Content), Description: "Create required file",
				}}}
			}
			return []sdk.Finding{result}, nil
		}
	case "forbid":
		findings := make([]sdk.Finding, 0, len(matches))
		for _, file := range matches {
			findings = append(findings, finding(rule, message, file.Path, "forbidden", 1, 1))
		}
		return findings, nil
	case "count":
		if (spec.Minimum > 0 && len(matches) < spec.Minimum) || (spec.Maximum > 0 && len(matches) > spec.Maximum) {
			return []sdk.Finding{finding(rule, fmt.Sprintf("%s (found %d)", message, len(matches)), "", "count", 0, 0)}, nil
		}
	}
	return nil, nil
}
