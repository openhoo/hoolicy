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
	if project.FailOn != "error" || project.Waivers != DefaultWaivers {
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
	if len(rules) != 1 || !ok || len(required) != 1 || required[0] != "README.md" || rules[0].Pack != "demo" || rules[0].PackVersion != "1.2.3" {
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

func TestProjectRejectsPathsThatRuntimeCannotResolve(t *testing.T) {
	t.Parallel()
	for _, path := range []string{".", " ../outside", "waivers.yaml\x00ignored"} {
		project := Project{Version: 1, Project: "demo", FailOn: "error", Waivers: path}
		if err := project.Validate(); err == nil || !strings.Contains(err.Error(), "waivers") {
			t.Fatalf("expected unsafe path rejection for %q, got %v", path, err)
		}
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
