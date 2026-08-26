package rules

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	gherkin "github.com/cucumber/gherkin/go/v30"
	"github.com/cucumber/messages/go/v24"
	"github.com/openhoo/hoolicy/sdk"
)

type GherkinRequirements struct{}

type gherkinSpec struct {
	Language          string   `yaml:"language,omitempty"`
	RequiredTags      []string `yaml:"requiredTags,omitempty"`
	EachScenarioAnyOf []string `yaml:"eachScenarioAnyOf,omitempty"`
	MinimumScenarios  int      `yaml:"minimumScenarios,omitempty"`
	Message           string   `yaml:"message"`
}

func (GherkinRequirements) Validate(rule sdk.Rule) error {
	if err := requireFiles(rule); err != nil {
		return err
	}
	var spec gherkinSpec
	if err := decodeSpec(rule, &spec); err != nil {
		return err
	}
	if spec.Language == "" {
		spec.Language = "en"
	}
	if len(spec.RequiredTags) == 0 && len(spec.EachScenarioAnyOf) == 0 && spec.MinimumScenarios == 0 {
		return fmt.Errorf("rule %s: gherkin.requirements needs a tag or scenario requirement", rule.ID)
	}
	for _, tag := range append(append([]string(nil), spec.RequiredTags...), spec.EachScenarioAnyOf...) {
		if strings.TrimSpace(strings.TrimPrefix(tag, "@")) == "" {
			return fmt.Errorf("rule %s: Gherkin tags must not be empty", rule.ID)
		}
	}
	return nil
}

func (GherkinRequirements) Evaluate(_ context.Context, input sdk.EvalContext, rule sdk.Rule) ([]sdk.Finding, error) {
	var spec gherkinSpec
	if err := decodeSpec(rule, &spec); err != nil {
		return nil, err
	}
	if spec.Language == "" {
		spec.Language = "en"
	}
	files, err := input.Repository.Match(rule.Files, rule.Exclude)
	if err != nil {
		return nil, err
	}
	message := spec.Message
	if message == "" {
		message = "Gherkin acceptance criteria are incomplete"
	}
	var findings []sdk.Finding
	for _, file := range files {
		counter := 0
		newID := func() string { counter++; return fmt.Sprintf("hoolicy-%d", counter) }
		document, parseErr := gherkin.ParseGherkinDocumentForLanguage(bytes.NewReader(file.Data), spec.Language, newID)
		if parseErr != nil {
			return nil, fmt.Errorf("%s: %w", file.Path, parseErr)
		}
		if document.Feature == nil {
			findings = append(findings, finding(rule, message+": feature is missing", file.Path, "feature", 1, 1))
			continue
		}
		if document.Feature.Language != spec.Language {
			findings = append(findings, finding(rule, fmt.Sprintf("%s: language is %s, expected %s", message, document.Feature.Language, spec.Language), file.Path, "language", locationLine(document.Feature.Location), locationColumn(document.Feature.Location)))
		}
		scenarios := collectScenarios(document.Feature)
		if spec.MinimumScenarios > 0 && len(scenarios) < spec.MinimumScenarios {
			findings = append(findings, finding(rule, fmt.Sprintf("%s: found %d scenarios, expected at least %d", message, len(scenarios), spec.MinimumScenarios), file.Path, "scenario-count", locationLine(document.Feature.Location), locationColumn(document.Feature.Location)))
		}
		present := map[string]bool{}
		for _, scenario := range scenarios {
			for _, tag := range scenario.Tags {
				present[normalizeTag(tag.Name)] = true
			}
			if len(spec.EachScenarioAnyOf) > 0 {
				matched := false
				for _, expected := range spec.EachScenarioAnyOf {
					if presentOnScenario(scenario, expected) {
						matched = true
						break
					}
				}
				if !matched {
					findings = append(findings, finding(rule, fmt.Sprintf("%s: scenario %q needs one of %s", message, scenario.Name, strings.Join(normalizeTags(spec.EachScenarioAnyOf), ", ")), file.Path, "scenario:"+scenario.Id, locationLine(scenario.Location), locationColumn(scenario.Location)))
				}
			}
		}
		for _, expected := range spec.RequiredTags {
			tag := normalizeTag(expected)
			if !present[tag] {
				findings = append(findings, finding(rule, fmt.Sprintf("%s: required scenario tag %s is missing", message, tag), file.Path, "tag:"+tag, locationLine(document.Feature.Location), locationColumn(document.Feature.Location)))
			}
		}
	}
	return findings, nil
}

func collectScenarios(feature *messages.Feature) []*messages.Scenario {
	var scenarios []*messages.Scenario
	for _, child := range feature.Children {
		if child.Scenario != nil {
			scenarios = append(scenarios, child.Scenario)
		}
		if child.Rule != nil {
			for _, ruleChild := range child.Rule.Children {
				if ruleChild.Scenario != nil {
					scenarios = append(scenarios, ruleChild.Scenario)
				}
			}
		}
	}
	return scenarios
}

func presentOnScenario(scenario *messages.Scenario, expected string) bool {
	expected = normalizeTag(expected)
	for _, tag := range scenario.Tags {
		if normalizeTag(tag.Name) == expected {
			return true
		}
	}
	return false
}

func normalizeTag(tag string) string { return "@" + strings.TrimPrefix(strings.TrimSpace(tag), "@") }
func normalizeTags(tags []string) []string {
	result := make([]string, len(tags))
	for i, tag := range tags {
		result[i] = normalizeTag(tag)
	}
	return result
}
func locationLine(location *messages.Location) int {
	if location == nil {
		return 1
	}
	return int(location.Line)
}
func locationColumn(location *messages.Location) int {
	if location == nil {
		return 1
	}
	return int(location.Column)
}
