package sdk

import (
	"fmt"
	"net/url"
	"strings"
	"unicode"
)

// Explanation is optional, policy-authored guidance. It describes the desired
// outcome and safe actions; steps are prose, never commands executed by Hoolicy.
type Explanation struct {
	Expectation string      `json:"expectation,omitempty" yaml:"expectation,omitempty"`
	Impact      string      `json:"impact,omitempty" yaml:"impact,omitempty"`
	Steps       []string    `json:"steps,omitempty" yaml:"steps,omitempty"`
	References  []Reference `json:"references,omitempty" yaml:"references,omitempty"`
}

type Reference struct {
	Title string `json:"title" yaml:"title"`
	URL   string `json:"url" yaml:"url"`
}

// PolicyContext carries the configured explanation into every report. It is
// bound by Finalize, so rule implementations cannot replace policy guidance.
// Historical finding digests do not include this presentation field. Its
// authoritative values are covered by RuleDigest and report identity checks.
type PolicyContext struct {
	Description string       `json:"description,omitempty"`
	Rationale   string       `json:"rationale,omitempty"`
	Kind        string       `json:"kind,omitempty"`
	PackVersion string       `json:"packVersion,omitempty"`
	Explanation *Explanation `json:"explanation,omitempty"`
}

func (rule Rule) PolicyContext() *PolicyContext {
	if rule.Description == "" && rule.Rationale == "" && rule.Kind == "" && rule.PackVersion == "" && rule.Explanation == nil {
		return nil
	}
	return &PolicyContext{Description: rule.Description, Rationale: rule.Rationale, Kind: rule.Kind, PackVersion: rule.PackVersion, Explanation: rule.Explanation.Clone()}
}

func (explanation *Explanation) Clone() *Explanation {
	if explanation == nil {
		return nil
	}
	copy := *explanation
	copy.Steps = append([]string(nil), explanation.Steps...)
	copy.References = append([]Reference(nil), explanation.References...)
	return &copy
}

// Validate bounds guidance and admits only credential-free absolute HTTPS
// references. References are emitted as data and are never fetched by checks.
func (explanation *Explanation) Validate() error {
	if explanation == nil {
		return nil
	}
	if explanation.Expectation == "" && explanation.Impact == "" && len(explanation.Steps) == 0 && len(explanation.References) == 0 {
		return fmt.Errorf("explanation must contain guidance")
	}
	for _, field := range []struct{ name, value string }{{"expectation", explanation.Expectation}, {"impact", explanation.Impact}} {
		if len(field.value) > 4096 || field.value != "" && strings.TrimSpace(field.value) == "" {
			return fmt.Errorf("explanation.%s must be nonblank and at most 4096 bytes", field.name)
		}
	}
	if len(explanation.Steps) > 16 || len(explanation.References) > 8 {
		return fmt.Errorf("explanation supports at most 16 steps and 8 references")
	}
	for index, step := range explanation.Steps {
		if strings.TrimSpace(step) == "" || len(step) > 4096 {
			return fmt.Errorf("explanation.steps[%d] must be nonblank and at most 4096 bytes", index)
		}
	}
	for index, reference := range explanation.References {
		if strings.TrimSpace(reference.Title) == "" || len(reference.Title) > 256 {
			return fmt.Errorf("explanation.references[%d].title must be nonblank and at most 256 bytes", index)
		}
		parsed, err := url.Parse(reference.URL)
		unsafe := strings.IndexFunc(reference.URL, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) || unicode.Is(unicode.Cf, r) }) >= 0
		if err != nil || unsafe || len(reference.URL) > 2048 || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Opaque != "" {
			return fmt.Errorf("explanation.references[%d].url must be an absolute HTTPS URL without credentials or query parameters (at most 2048 bytes)", index)
		}
	}
	return nil
}
