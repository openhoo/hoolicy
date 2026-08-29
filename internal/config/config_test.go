package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openhoo/hoolicy/sdk"
)

func TestValidateRuleAcceptsCustomKindAndRejectsMalformedKind(t *testing.T) {
	t.Parallel()
	rule := sdk.Rule{ID: "demo.rule", Title: "Demo", Description: "Demo rule.", Rationale: "Needed for testing.", Remediation: "Correct it.", Severity: sdk.SeverityError, Kind: "company.custom-kind"}
	if problems := ValidateRule(rule); len(problems) != 0 {
		t.Fatalf("valid custom kind rejected: %v", problems)
	}
	rule.Kind = "company_custom"
	if problems := ValidateRule(rule); len(problems) == 0 || !strings.Contains(strings.Join(problems, " "), "kind must") {
		t.Fatalf("malformed kind accepted: %v", problems)
	}
}

func TestLoadProjectIsStrict(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	valid := "version: 1\nproject: demo\nrules: []\n"
	path := filepath.Join(root, DefaultFilename)
	writeTestFile(t, path, valid)
	project, err := LoadProject(path)
	if err != nil {
		t.Fatal(err)
	}
	if project.FailOn != "error" || project.Waivers != DefaultWaivers || project.Baseline != DefaultBaseline {
		t.Fatalf("defaults not applied: %#v", project)
	}

	for name, body := range map[string]string{
		"unknown field": valid + "surprise: true\n",
		"duplicate key": "version: 1\nproject: demo\nproject: shadow\n",
		"two documents": valid + "---\nversion: 1\nproject: other\n",
	} {
		t.Run(name, func(t *testing.T) {
			candidate := filepath.Join(root, strings.ReplaceAll(name, " ", "-")+".yaml")
			writeTestFile(t, candidate, body)
			if _, err := LoadProject(candidate); err == nil {
				t.Fatal("expected strict decoding error")
			}
		})
	}
}

func TestBaselineRoundTripAndStrictValidation(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	path := filepath.Join(root, DefaultBaseline)
	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	baseline := BaselineFile{
		Version: 1, Project: "demo", CreatedAt: now, ToolVersion: "0.2.0",
		Revision: strings.Repeat("a", 40), PolicyDigest: "sha256:" + strings.Repeat("b", 64),
		Entries: []BaselineEntry{{
			Fingerprint: strings.Repeat("c", 64), RuleID: "demo.rule", Severity: sdk.SeverityError,
			PolicyDigest: "sha256:" + strings.Repeat("d", 64), FindingDigest: "sha256:" + strings.Repeat("e", 64), CreatedAt: now,
		}},
	}
	if err := SaveBaseline(path, baseline); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadBaseline(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Entries) != 1 || loaded.Entries[0].RuleID != "demo.rule" {
		t.Fatalf("unexpected baseline: %#v", loaded)
	}
	writeTestFile(t, path, `{"version":1,"project":"demo","createdAt":"2026-08-28T12:00:00Z","toolVersion":"test","policyDigest":"sha256:`+strings.Repeat("b", 64)+`","entries":[],"unknown":true}`)
	if _, err := LoadBaseline(path); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("expected strict baseline rejection, got %v", err)
	}
	baseline.Entries = append(baseline.Entries, baseline.Entries[0])
	if err := ValidateBaseline(baseline); err == nil || !strings.Contains(err.Error(), "duplicates fingerprint") {
		t.Fatalf("expected duplicate rejection, got %v", err)
	}
}

func TestLoadPackAndInstantiate(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "pack.yaml"), `version: 1
name: demo
release: 1.2.3
description: Demo policy pack.
parameters:
  paths:
    type: string_list
    required: true
    description: Files to check.
rules:
  - id: demo.readme
    title: README exists
    description: Requires documentation.
    rationale: Humans need context.
    remediation: Add README.
    severity: error
    kind: text
    files: [README.md]
    exclude: ["{{ paths }}"]
    spec:
      require: "{{ paths }}"
      message: Missing README
`)
	pack, err := LoadPack(root)
	if err != nil {
		t.Fatal(err)
	}
	rules, err := pack.Instantiate(map[string]any{"paths": []any{"README.md"}})
	if err != nil {
		t.Fatal(err)
	}
	required, ok := rules[0].Spec["require"].([]any)
	if len(rules) != 1 || !ok || len(required) != 1 || required[0] != "README.md" || len(rules[0].Exclude) != 1 || rules[0].Exclude[0] != "README.md" || rules[0].Pack != "demo" || rules[0].PackVersion != "1.2.3" {
		t.Fatalf("unexpected instantiated rule: %#v", rules)
	}
	if _, err := pack.Instantiate(map[string]any{"unknown": true}); err == nil {
		t.Fatal("expected unknown parameter error")
	}
}

func TestLoadPackRequiresRules(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "pack.yaml"), "version: 1\nname: empty\nrelease: 1.0.0\ndescription: Empty pack.\nrules: []\n")
	if _, err := LoadPack(root); err == nil || !strings.Contains(err.Error(), "at least one rule") {
		t.Fatalf("expected empty-pack rejection, got %v", err)
	}
}

func TestPackParameterErrorsAreDeterministic(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "pack.yaml"), `version: 1
name: demo
release: 1.0.0
description: Demo pack.
parameters:
  zed: {type: invalid, description: Zed parameter.}
  alpha: {type: invalid, description: Alpha parameter.}
rules:
  - id: demo.rule
    title: Demo
    description: Demo rule.
    rationale: Needed for testing.
    remediation: Correct it.
    severity: error
    kind: files
    files: [README.md]
    spec: {mode: require}
`)
	if _, err := LoadPack(root); err == nil || !strings.Contains(err.Error(), "parameter alpha") {
		t.Fatalf("unexpected parameter validation error: %v", err)
	}
	pack := &Pack{Name: "demo", Parameters: map[string]Parameter{"known": {Type: "string"}}}
	if _, err := pack.Instantiate(map[string]any{"zed": true, "alpha": true}); err == nil || !strings.Contains(err.Error(), "unknown parameter alpha") {
		t.Fatalf("unexpected instantiation error: %v", err)
	}
}

func TestPackCompatibilityRangesFailBeforeEvaluation(t *testing.T) {
	t.Parallel()
	pack := &Pack{Name: "demo", Compatibility: Compatibility{Config: ">=1 <2", Hoolicy: ">=0.2.0 <1.0.0"}}
	if err := ValidatePackCompatibility(pack, "0.2.0"); err != nil {
		t.Fatal(err)
	}
	if err := ValidatePackCompatibility(pack, "0.1.9"); err == nil || !strings.Contains(err.Error(), "requires Hoolicy") {
		t.Fatalf("expected old engine rejection, got %v", err)
	}
	if err := ValidatePackCompatibility(pack, "1.0.0"); err == nil || !strings.Contains(err.Error(), "requires Hoolicy") {
		t.Fatalf("expected major engine rejection, got %v", err)
	}
	pack.Compatibility.Hoolicy = ">=1.0.0 <2.0.0"
	if err := ValidatePackCompatibility(pack, "1.0.0-rc.1"); err == nil || !strings.Contains(err.Error(), "requires Hoolicy") {
		t.Fatalf("expected prerelease lower-bound rejection, got %v", err)
	}
	pack.Compatibility.Hoolicy = ">=0.2.0 <1.0.0"
	pack.Compatibility.Config = ">=2 <3"
	if err := ValidatePackCompatibility(pack, "0.2.0"); err == nil || !strings.Contains(err.Error(), "requires config") {
		t.Fatalf("expected config rejection, got %v", err)
	}
	pack.Compatibility.Config = "^1"
	if err := ValidatePackCompatibility(pack, "0.2.0"); err == nil || !strings.Contains(err.Error(), "unsupported range") {
		t.Fatalf("expected invalid range rejection, got %v", err)
	}
}

func TestLoadLockIsStrictAndValidatesEntries(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	path := filepath.Join(root, DefaultLockfile)
	writeTestFile(t, path, `{"version":1,"packs":[]} {"trailing":true}`)
	if _, err := LoadLock(path); err == nil || !strings.Contains(err.Error(), "exactly one JSON value") {
		t.Fatalf("expected trailing JSON rejection, got %v", err)
	}
	writeTestFile(t, path, `{"version":1,"packs":[{"name":"demo","git":"https://token@example.com/repo.git","ref":"main","commit":"0123456789abcdef0123456789abcdef01234567","digest":"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","vendor":".hoolicy/vendor/demo"}]}`)
	if _, err := LoadLock(path); err == nil || !strings.Contains(err.Error(), "embedded credentials") {
		t.Fatalf("expected credential rejection, got %v", err)
	}
}

func TestProjectRejectsUnsafeRemotePackInputs(t *testing.T) {
	t.Parallel()
	base := Project{Version: 1, Project: "demo", FailOn: "error", Packs: []PackRef{{Name: "pack", Git: "git@github.com:example/policy.git", Ref: "main"}}}
	if err := base.Validate(); err != nil {
		t.Fatalf("valid SSH location rejected: %v", err)
	}
	credential := base
	credential.Packs = []PackRef{{Name: "pack", Git: "https://token@example.com/policy.git", Ref: "main"}}
	if err := credential.Validate(); err == nil || !strings.Contains(err.Error(), "embedded credentials") {
		t.Fatalf("expected credential rejection, got %v", err)
	}
	query := base
	query.Packs = []PackRef{{Name: "pack", Git: "https://example.com/policy.git?token=secret", Ref: "main"}}
	if err := query.Validate(); err == nil || !strings.Contains(err.Error(), "query strings") {
		t.Fatalf("expected query-string rejection, got %v", err)
	}
	option := base
	option.Packs = []PackRef{{Name: "pack", Git: "https://example.com/policy.git", Ref: "--upload-pack=evil"}}
	if err := option.Validate(); err == nil || !strings.Contains(err.Error(), ".ref is unsafe") {
		t.Fatalf("expected option-like ref rejection, got %v", err)
	}
}

func TestProjectAcceptsExplicitOCIAndRejectsAmbiguousOrMutableReferences(t *testing.T) {
	t.Parallel()
	valid := Project{Version: 1, Project: "demo", FailOn: "error", Packs: []PackRef{{Name: "policy", OCI: "ghcr.io/openhoo/policy:v1.2.3"}}}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, reference := range map[string]PackRef{
		"no tag":    {Name: "policy", OCI: "ghcr.io/openhoo/policy"},
		"scheme":    {Name: "policy", OCI: "https://ghcr.io/openhoo/policy:v1"},
		"ambiguous": {Name: "policy", OCI: "ghcr.io/openhoo/policy:v1", Git: "https://example.com/policy.git", Ref: "v1"},
	} {
		candidate := valid
		candidate.Packs = []PackRef{reference}
		if err := candidate.Validate(); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}

func TestSemanticVersionPrecedence(t *testing.T) {
	t.Parallel()
	ordered := []string{"1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta", "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0", "1.0.1"}
	for index := 1; index < len(ordered); index++ {
		comparison, err := CompareSemanticVersions(ordered[index-1], ordered[index])
		if err != nil || comparison >= 0 {
			t.Fatalf("expected %s before %s: comparison=%d err=%v", ordered[index-1], ordered[index], comparison, err)
		}
	}
	if comparison, err := CompareSemanticVersions("1.0.0+first", "1.0.0+second"); err != nil || comparison != 0 {
		t.Fatalf("build metadata affected precedence: comparison=%d err=%v", comparison, err)
	}
	for _, invalid := range []string{"1.0.0-01", "1.0", "v1.0.0"} {
		if _, err := CompareSemanticVersions(invalid, "1.0.0"); err == nil {
			t.Fatalf("accepted invalid semantic version %s", invalid)
		}
	}
}

func TestCompatibilityRangesSupportExplicitPrereleaseAlternative(t *testing.T) {
	t.Parallel()
	constraint := ">=0.1.3-0 <0.1.3 || >=0.2.0 <2.0.0"
	for _, version := range []string{"0.1.3-0.20260827192717-081c2b065b8d", "0.2.0", "1.9.9"} {
		if ok, err := versionSatisfies(version, constraint); err != nil || !ok {
			t.Fatalf("%s should satisfy %q: ok=%v err=%v", version, constraint, ok, err)
		}
	}
	for _, version := range []string{"0.1.2", "0.1.3", "2.0.0"} {
		if ok, err := versionSatisfies(version, constraint); err != nil || ok {
			t.Fatalf("%s should not satisfy %q: ok=%v err=%v", version, constraint, ok, err)
		}
	}
	if _, err := versionSatisfies("1.0.0", ">=1 ||"); err == nil {
		t.Fatal("empty compatibility alternative accepted")
	}
}

func TestTrustPolicyRequiresNarrowExplicitVerification(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	path := filepath.Join(root, "trust.yaml")
	writeTestFile(t, path, `version: 1
requirements:
  - name: official
    registry: ghcr.io/openhoo/*
    identity: https://github.com/openhoo/policy/.github/workflows/publish.yml@refs/tags/v1
    issuer: https://token.actions.githubusercontent.com
  - name: internal-key
    registry: registry.example.com/policy/*
    key: keys/policy.pub
`)
	trust, err := LoadTrust(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(trust.Requirements) != 2 {
		t.Fatalf("unexpected trust: %#v", trust)
	}
	writeTestFile(t, path, "version: 1\nrequirements:\n  - name: broad\n    registry: '*'\n    identity: anything\n    issuer: https://issuer.example.com\n")
	if _, err := LoadTrust(path); err == nil || !strings.Contains(err.Error(), "narrow") {
		t.Fatalf("global trust accepted: %v", err)
	}
}

func TestProjectRejectsPathsThatRuntimeCannotResolve(t *testing.T) {
	t.Parallel()
	for _, path := range []string{".", " ../outside", "waivers.yaml\x00ignored", "/outside", "C:/outside", `C:\outside`, `..\outside`} {
		project := Project{Version: 1, Project: "demo", FailOn: "error", Waivers: path}
		if err := project.Validate(); err == nil || !strings.Contains(err.Error(), "waivers") {
			t.Fatalf("expected unsafe path rejection for %q, got %v", path, err)
		}
	}
}

func TestProjectLoaderRejectsOversizedPolicyInput(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), DefaultFilename)
	writeTestFile(t, path, "version: 1\nproject: demo\n")
	if err := os.Truncate(path, maxPolicyInputBytes+1); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadProject(path); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized policy input accepted: %v", err)
	}
}

func TestValidateWaiver(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 26, 0, 0, 0, 0, time.UTC)
	valid := Waiver{
		ID: "security.cve-1", Rule: "supply-chain.exception-lifecycle",
		Fingerprints: []string{strings.Repeat("a", 64)},
		Reason:       "Temporary upstream remediation is still pending.",
		Owner:        "security@example.com", Ticket: "https://issues.example.com/SEC-1",
		Created: Date{Time: now.AddDate(0, 0, -1)}, Expires: Date{Time: now.AddDate(0, 1, 0)},
	}
	if err := ValidateWaiver(valid, now); err != nil {
		t.Fatal(err)
	}
	if err := ValidateWaiverForProject(valid, now, true); err == nil || !strings.Contains(err.Error(), "approver") {
		t.Fatalf("required approver accepted: %v", err)
	}
	valid.Approver = "security-review@example.com"
	if err := ValidateWaiverForProject(valid, now, true); err != nil {
		t.Fatal(err)
	}
	tests := map[string]func(*Waiver){
		"fingerprint":            func(value *Waiver) { value.Fingerprints = []string{"ABC"} },
		"global path":            func(value *Waiver) { value.Fingerprints = nil; value.Paths = []string{"**/*"} },
		"obfuscated global path": func(value *Waiver) { value.Fingerprints = nil; value.Paths = []string{"**/**"} },
		"invalid path glob":      func(value *Waiver) { value.Fingerprints = nil; value.Paths = []string{"[broken"} },
		"ticket":                 func(value *Waiver) { value.Ticket = "SEC-1" },
		"lifetime":               func(value *Waiver) { value.Expires = Date{Time: now.AddDate(0, 0, 91)} },
		"expired": func(value *Waiver) {
			value.Created = Date{Time: now.AddDate(0, 0, -40)}
			value.Expires = Date{Time: now.AddDate(0, 0, -1)}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			candidate.Fingerprints = append([]string(nil), valid.Fingerprints...)
			mutate(&candidate)
			if err := ValidateWaiver(candidate, now); err == nil {
				t.Fatal("expected invalid waiver")
			}
		})
	}
}

func TestWorkspaceValidationRejectsCyclesUnknownPacksAndParameterConflicts(t *testing.T) {
	t.Parallel()
	project := &Project{Version: 1, Project: "demo", FailOn: sdk.SeverityError, Workspaces: []Workspace{
		{Name: "api", Paths: []string{"services/api/**"}, Owner: "@api", Packs: []string{"missing"}, DependsOn: []string{"shared", "api"}},
		{Name: "shared", Paths: []string{"shared/**"}, Owner: "@platform", Parameters: map[string]any{"region": "eu"}, DependsOn: []string{"other"}},
		{Name: "other", Paths: []string{"other/**"}, Owner: "@platform", Parameters: map[string]any{"region": "us"}},
	}}
	err := project.Validate()
	if err == nil {
		t.Fatal("invalid workspaces accepted")
	}
	for _, expected := range []string{"unknown pack", "dependency cycle", "conflicting dependency parameter"} {
		if !strings.Contains(err.Error(), expected) {
			t.Fatalf("missing %q in %v", expected, err)
		}
	}
}

func TestLoadYAMLStrictRejectsSymlink(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	target := filepath.Join(root, "target.yaml")
	link := filepath.Join(root, "link.yaml")
	writeTestFile(t, target, "version: 1\nproject: demo\n")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	var project Project
	if err := LoadYAMLStrict(link, &project); err == nil || !strings.Contains(err.Error(), "symbolic links are forbidden") {
		t.Fatalf("expected symlink rejection, got %v", err)
	}
}

func writeTestFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}
