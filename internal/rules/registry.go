package rules

import "github.com/openhoo/hoolicy/sdk"

func RegisterCore(registry *sdk.Registry) error {
	for name, kind := range map[string]sdk.RuleKind{
		"files":                Files{},
		"text":                 Text{},
		"structured.cel":       CEL{},
		"git.naming":           GitNaming{},
		"manifest.consistency": ManifestConsistency{},
		"sources.allowed":      SourcesAllowed{},
		"exceptions.lifecycle": ExceptionsLifecycle{},
		"i18n.parity":          I18nParity{},
		"gherkin.requirements": GherkinRequirements{},
	} {
		if err := registry.Register(name, kind); err != nil {
			return err
		}
	}
	return nil
}
