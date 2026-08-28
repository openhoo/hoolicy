package rules

import "github.com/openhoo/hoolicy/sdk"

func RegisterCore(registry *sdk.Registry) error {
	celKind, err := newCEL()
	if err != nil {
		return err
	}
	for name, kind := range map[string]sdk.RuleKind{
		"files":                 Files{},
		"text":                  Text{},
		"structured.cel":        celKind,
		"ci.workflow-security":  CIWorkflowSecurity{},
		"artifact.evidence":     ArtifactEvidence{},
		"dependency.governance": DependencyGovernance{},
		"deployment.invariants": DeploymentInvariants{},
		"api.contract":          APIContract{},
		"git.naming":            GitNaming{},
		"manifest.consistency":  ManifestConsistency{},
		"sources.allowed":       SourcesAllowed{},
		"exceptions.lifecycle":  ExceptionsLifecycle{},
		"i18n.parity":           I18nParity{},
		"gherkin.requirements":  GherkinRequirements{},
	} {
		if err := registry.Register(name, kind); err != nil {
			return err
		}
	}
	return nil
}
