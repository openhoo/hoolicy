package engine_test

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openhoo/hoolicy/internal/config"
	"github.com/openhoo/hoolicy/internal/engine"
	"github.com/openhoo/hoolicy/internal/rules"
	"github.com/openhoo/hoolicy/sdk"
)

const parameterPack = `version: 1
name: limits
release: 0.1.0
description: Exposes checked parameters to CEL.
compatibility: {config: '>=1 <2', hoolicy: '>=0.0.0 <1.0.0'}
parameters:
  minimum_replicas: {type: number, default: 2, description: Minimum replicas.}
  environments: {type: string_list, required: true, description: Checked environments.}
  strict: {type: bool, default: false, description: Strict mode.}
rules:
  - id: limits.replicas
    title: Replica floor
    description: Uses pack parameters inside a CEL expression.
    rationale: Parameters must be usable within expressions.
    remediation: Raise replicas.
    severity: error
    kind: structured.cel
    files: [deploy.json]
    spec:
      format: json
      expression: "documents.filter(d, d.data.replicas < pack.minimum_replicas && d.data.environment in pack.environments).map(d, {'message': 'replicas below ' + string(pack.minimum_replicas) + ' strict=' + string(pack.strict) + ' shadow=' + string('minimum_replicas' in params), 'path': d.path})"
      message: Replica floor violated
  - id: limits.readme
    title: README exists
    description: Non-CEL rule from the same pack.
    rationale: Unrelated parameters must not change this rule's identity.
    remediation: Add README.md.
    severity: warning
    kind: files
    files: [README.md]
    spec: {mode: require, message: README missing}
`

func packParameterProject(minimum string) string {
	return `version: 1
project: demo
parameters:
  minimum_replicas: 99
packs:
  - name: limits
    path: .hoolicy/packs/limits
    with:
      environments: [production]
` + minimum + `rules:
  - id: demo.project-cel
    title: Project CEL
    description: Project rules see an empty pack map.
    rationale: Pack parameters belong to packs only.
    remediation: None.
    severity: error
    kind: structured.cel
    files: [deploy.json]
    spec:
      format: json
      expression: "pack.size() == 0 && params.minimum_replicas == 99"
      message: project rule saw pack parameters
`
}

func checkPackParameters(t *testing.T, minimum string) (*engine.Report, []sdk.Rule) {
	t.Helper()
	root := t.TempDir()
	writeEngineFile(t, filepath.Join(root, ".hoolicy", "packs", "limits", "pack.yaml"), parameterPack)
	writeEngineFile(t, filepath.Join(root, "deploy.json"), `{"replicas":3,"environment":"production"}`)
	writeEngineFile(t, filepath.Join(root, "README.md"), "demo\n")
	writeEngineFile(t, filepath.Join(root, config.DefaultFilename), packParameterProject(minimum))
	project, err := config.LoadProject(filepath.Join(root, config.DefaultFilename))
	if err != nil {
		t.Fatal(err)
	}
	registry := sdk.NewRegistry()
	if err := rules.RegisterCore(registry); err != nil {
		t.Fatal(err)
	}
	checker := engine.NewWithVersion(registry, "0.6.0")
	active, err := checker.Validate(project)
	if err != nil {
		t.Fatal(err)
	}
	report, err := checker.Check(context.Background(), project, engine.Options{ToolVersion: "0.6.0"})
	if err != nil {
		t.Fatal(err)
	}
	return report, active
}

func ruleByID(t *testing.T, active []sdk.Rule, id string) sdk.Rule {
	t.Helper()
	for _, rule := range active {
		if rule.ID == id {
			return rule
		}
	}
	t.Fatalf("rule %s missing", id)
	return sdk.Rule{}
}

func TestCELPackParametersAreVisibleShadowFreeAndDigested(t *testing.T) {
	t.Parallel()
	// Default minimum (2) passes; project params.minimum_replicas=99 must
	// not shadow the pack value.
	passing, passingRules := checkPackParameters(t, "")
	if len(passing.Findings) != 0 {
		t.Fatalf("project parameter shadowed pack parameter or project rule saw pack map: %#v", passing.Findings)
	}
	failing, failingRules := checkPackParameters(t, "      minimum_replicas: 5\n")
	if len(failing.Findings) != 1 {
		t.Fatalf("with: value not visible to CEL: %#v", failing.Findings)
	}
	if got := failing.Findings[0].Message; got != "replicas below 5 strict=false shadow=true" {
		t.Fatalf("unexpected pack-parameter message %q", got)
	}
	before, after := ruleByID(t, passingRules, "limits.replicas"), ruleByID(t, failingRules, "limits.replicas")
	if sdk.RuleDigest(before) == sdk.RuleDigest(after) {
		t.Fatal("changing with: did not change the CEL rule's policy digest")
	}
	if sdk.RuleDigest(ruleByID(t, passingRules, "limits.readme")) != sdk.RuleDigest(ruleByID(t, failingRules, "limits.readme")) {
		t.Fatal("unrelated pack parameter changed a non-CEL rule's policy digest")
	}
	if project := ruleByID(t, passingRules, "demo.project-cel"); project.PackParameters != nil {
		t.Fatalf("project rule carries pack parameters: %#v", project.PackParameters)
	}
	if got := before.PackParameters["environments"]; len(got.([]any)) != 1 {
		t.Fatalf("string list parameter not normalized: %#v", got)
	}
}

// The digest was computed with the pre-feature engine (commit b24a2b0) for
// the published pack and minimum_replicas: 3. A CEL rule that does not read
// pack must keep its policy identity so existing baselines stay valid.
const preFeatureNoWildcardOriginsDigest = "sha256:907bf0789f9a144d58558282fb75e496257894d5ff49e18f27c3cc8d4830cceb"

func TestCELRuleWithoutPackReferenceKeepsPreFeatureDigest(t *testing.T) {
	t.Parallel()
	pack, err := config.LoadPack(filepath.Join("..", "..", "packs", "structured-configuration"))
	if err != nil {
		t.Fatal(err)
	}
	instantiated, err := pack.Instantiate(map[string]any{"minimum_replicas": 3})
	if err != nil {
		t.Fatal(err)
	}
	rule := ruleByID(t, instantiated, "structured-configuration.no-wildcard-origins")
	if rule.PackParameters != nil {
		t.Fatalf("pack parameters attached to a rule that never reads pack: %#v", rule.PackParameters)
	}
	if got := sdk.RuleDigest(rule); got != preFeatureNoWildcardOriginsDigest {
		t.Fatalf("policy digest changed: %s", got)
	}
}

func TestCELPackParametersAttachOnlyWhenExpressionReadsPack(t *testing.T) {
	t.Parallel()
	pack := &config.Pack{Name: "probe", Release: "0.1.0", Parameters: map[string]config.Parameter{
		"limit": {Type: "number", Default: 1, Description: "Limit."},
	}}
	for expression, attached := range map[string]bool{
		"pack.limit > 0":                     true,
		"'pack' in params":                   false,
		"[1].all(pack, pack > 0)":            false,
		"documents.all(d, d.path != 'pack')": false,
	} {
		pack.Rules = []sdk.Rule{{ID: "probe.rule", Title: "Probe", Description: "Probe.", Rationale: "Probe.", Remediation: "Probe.", Severity: sdk.SeverityError, Kind: "structured.cel", Files: []string{"a.json"}, Spec: map[string]any{"expression": expression, "message": "m"}}}
		rules, err := pack.Instantiate(nil)
		if err != nil {
			t.Fatal(err)
		}
		if got := rules[0].PackParameters != nil; got != attached {
			t.Fatalf("%s: attached=%v, want %v", expression, got, attached)
		}
	}
}

func TestCELPackParametersAreStaticallyTyped(t *testing.T) {
	t.Parallel()
	kind := rules.CEL{}
	for expression, valid := range map[string]bool{
		"pack.size() >= 0":          true,
		"'x' in pack":               true,
		"pack.limit > 1":            true,
		"pack == 1":                 false,
		"pack.exists(k, k == 1)":    false,
		"undefinedVariable == pack": false,
	} {
		rule := sdk.Rule{ID: "demo.cel", Kind: "structured.cel", Files: []string{"a.json"}, Spec: map[string]any{"expression": expression, "message": "m"}}
		err := kind.Validate(rule)
		if (err == nil) != valid {
			t.Fatalf("%s: valid=%v err=%v", expression, valid, err)
		}
		if err != nil && !strings.Contains(err.Error(), "CEL compile") {
			t.Fatalf("%s: unexpected error %v", expression, err)
		}
	}
}
