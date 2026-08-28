package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/openhoo/hoolicy/internal/repository"
	"github.com/openhoo/hoolicy/sdk"
	"go.yaml.in/yaml/v3"
)

const (
	CurrentVersion      = 1
	maxPolicyInputBytes = 16 << 20
	DefaultFilename     = "hoolicy.yaml"
	DefaultLockfile     = "hoolicy.lock"
	DefaultWaivers      = ".hoolicy/waivers.yaml"
	DefaultBaseline     = ".hoolicy/baseline.json"
	DefaultTrust        = ".hoolicy/trust.yaml"
	DefaultEvidence     = ".hoolicy/evidence.yaml"
)

var (
	projectNamePattern   = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)
	ruleIDPattern        = regexp.MustCompile(`^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$`)
	fingerprintPattern   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	commitPattern        = regexp.MustCompile(`^[0-9a-f]{40}$`)
	digestPattern        = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	semverPattern        = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`)
	rangeTokenPattern    = regexp.MustCompile(`^(>=|<=|>|<|=)?([0-9]+(?:\.[0-9]+){0,2}(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?)$`)
	ociRegistryPattern   = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?(?::[0-9]{1,5})?$`)
	ociRepositoryPattern = regexp.MustCompile(`^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*$`)
	ociTagPattern        = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$`)
)

type Project struct {
	Version               int             `yaml:"version" json:"version"`
	Project               string          `yaml:"project" json:"project"`
	FailOn                sdk.Severity    `yaml:"failOn,omitempty" json:"failOn,omitempty"`
	Waivers               string          `yaml:"waivers,omitempty" json:"waivers,omitempty"`
	Baseline              string          `yaml:"baseline,omitempty" json:"baseline,omitempty"`
	Trust                 string          `yaml:"trust,omitempty" json:"trust,omitempty"`
	Evidence              string          `yaml:"evidence,omitempty" json:"evidence,omitempty"`
	RequireWaiverApprover bool            `yaml:"requireWaiverApprover,omitempty" json:"requireWaiverApprover,omitempty"`
	Workspaces            []Workspace     `yaml:"workspaces,omitempty" json:"workspaces,omitempty"`
	Budgets               ResourceBudgets `yaml:"budgets,omitempty" json:"budgets,omitempty"`
	Parameters            map[string]any  `yaml:"parameters,omitempty" json:"parameters,omitempty"`
	Packs                 []PackRef       `yaml:"packs,omitempty" json:"packs,omitempty"`
	Rules                 []sdk.Rule      `yaml:"rules,omitempty" json:"rules,omitempty"`
	Root                  string          `yaml:"-" json:"-"`
	Path                  string          `yaml:"-" json:"-"`
}

type Workspace struct {
	Name       string         `yaml:"name" json:"name"`
	Paths      []string       `yaml:"paths" json:"paths"`
	Owner      string         `yaml:"owner" json:"owner"`
	Packs      []string       `yaml:"packs,omitempty" json:"packs,omitempty"`
	Parameters map[string]any `yaml:"parameters,omitempty" json:"parameters,omitempty"`
	DependsOn  []string       `yaml:"dependsOn,omitempty" json:"dependsOn,omitempty"`
}

type ResourceBudgets struct {
	MaximumFiles         int    `yaml:"maximumFiles,omitempty" json:"maximumFiles,omitempty"`
	MaximumDocumentBytes int64  `yaml:"maximumDocumentBytes,omitempty" json:"maximumDocumentBytes,omitempty"`
	MaximumFindings      int    `yaml:"maximumFindings,omitempty" json:"maximumFindings,omitempty"`
	MaximumRuleDuration  string `yaml:"maximumRuleDuration,omitempty" json:"maximumRuleDuration,omitempty"`
	MaximumTotalDuration string `yaml:"maximumTotalDuration,omitempty" json:"maximumTotalDuration,omitempty"`
}

type PackRef struct {
	Name   string         `yaml:"name" json:"name"`
	Path   string         `yaml:"path,omitempty" json:"path,omitempty"`
	Git    string         `yaml:"git,omitempty" json:"git,omitempty"`
	Ref    string         `yaml:"ref,omitempty" json:"ref,omitempty"`
	Subdir string         `yaml:"subdir,omitempty" json:"subdir,omitempty"`
	OCI    string         `yaml:"oci,omitempty" json:"oci,omitempty"`
	With   map[string]any `yaml:"with,omitempty" json:"with,omitempty"`
}

type Parameter struct {
	Type        string `yaml:"type" json:"type"`
	Required    bool   `yaml:"required,omitempty" json:"required,omitempty"`
	Description string `yaml:"description" json:"description"`
	Default     any    `yaml:"default,omitempty" json:"default,omitempty"`
}

type Pack struct {
	Version            int                  `yaml:"version" json:"version"`
	Name               string               `yaml:"name" json:"name"`
	Release            string               `yaml:"release" json:"release"`
	Description        string               `yaml:"description" json:"description"`
	Maturity           string               `yaml:"maturity,omitempty" json:"maturity,omitempty"`
	Owner              string               `yaml:"owner,omitempty" json:"owner,omitempty"`
	CompatibilityNotes string               `yaml:"compatibilityNotes,omitempty" json:"compatibilityNotes,omitempty"`
	Compatibility      Compatibility        `yaml:"compatibility,omitempty" json:"compatibility,omitempty"`
	Parameters         map[string]Parameter `yaml:"parameters,omitempty" json:"parameters,omitempty"`
	Rules              []sdk.Rule           `yaml:"rules" json:"rules"`
}

type Compatibility struct {
	Config  string `yaml:"config,omitempty" json:"config,omitempty"`
	Hoolicy string `yaml:"hoolicy,omitempty" json:"hoolicy,omitempty"`
}

type Lock struct {
	Version int          `json:"version"`
	Packs   []LockedPack `json:"packs"`
}

type LockedPack struct {
	Name           string `json:"name"`
	Git            string `json:"git"`
	Ref            string `json:"ref"`
	Subdir         string `json:"subdir,omitempty"`
	Commit         string `json:"commit"`
	Digest         string `json:"digest"`
	Vendor         string `json:"vendor"`
	Release        string `json:"release,omitempty"`
	OCI            string `json:"oci,omitempty"`
	ManifestDigest string `json:"manifestDigest,omitempty"`
	PackDigest     string `json:"packDigest,omitempty"`
	VerifiedBy     string `json:"verifiedBy,omitempty"`
}

type TrustPolicy struct {
	Version      int                `yaml:"version" json:"version"`
	Requirements []TrustRequirement `yaml:"requirements" json:"requirements"`
}

type TrustRequirement struct {
	Name     string `yaml:"name" json:"name"`
	Registry string `yaml:"registry" json:"registry"`
	Identity string `yaml:"identity,omitempty" json:"identity,omitempty"`
	Issuer   string `yaml:"issuer,omitempty" json:"issuer,omitempty"`
	Key      string `yaml:"key,omitempty" json:"key,omitempty"`
}

type Catalog struct {
	Version     int            `json:"version"`
	Name        string         `json:"name"`
	GeneratedAt time.Time      `json:"generatedAt"`
	Packs       []CatalogEntry `json:"packs"`
}

type CatalogEntry struct {
	Name    string `json:"name"`
	Release string `json:"release"`
	OCI     string `json:"oci"`
}

type CatalogLock struct {
	Version        int    `json:"version"`
	Source         string `json:"source"`
	ManifestDigest string `json:"manifestDigest"`
	CatalogDigest  string `json:"catalogDigest"`
	VerifiedBy     string `json:"verifiedBy"`
}

type WaiverFile struct {
	Version int      `yaml:"version" json:"version"`
	Waivers []Waiver `yaml:"waivers" json:"waivers"`
}

type Waiver struct {
	ID           string   `yaml:"id" json:"id"`
	Rule         string   `yaml:"rule" json:"rule"`
	Fingerprints []string `yaml:"fingerprints,omitempty" json:"fingerprints,omitempty"`
	Paths        []string `yaml:"paths,omitempty" json:"paths,omitempty"`
	Reason       string   `yaml:"reason" json:"reason"`
	Owner        string   `yaml:"owner" json:"owner"`
	Ticket       string   `yaml:"ticket" json:"ticket"`
	Approver     string   `yaml:"approver,omitempty" json:"approver,omitempty"`
	Created      Date     `yaml:"created" json:"created"`
	Expires      Date     `yaml:"expires" json:"expires"`
}

type BaselineFile struct {
	Version      int             `json:"version"`
	Project      string          `json:"project"`
	CreatedAt    time.Time       `json:"createdAt"`
	ToolVersion  string          `json:"toolVersion"`
	Revision     string          `json:"revision,omitempty"`
	PolicyDigest string          `json:"policyDigest"`
	Entries      []BaselineEntry `json:"entries"`
}

type BaselineEntry struct {
	Fingerprint   string       `json:"fingerprint"`
	RuleID        string       `json:"ruleId"`
	Severity      sdk.Severity `json:"severity"`
	PolicyDigest  string       `json:"policyDigest"`
	FindingDigest string       `json:"findingDigest"`
	CreatedAt     time.Time    `json:"createdAt"`
}

type Date struct {
	time.Time
}

func (d *Date) UnmarshalYAML(node *yaml.Node) error {
	parsed, err := time.Parse("2006-01-02", node.Value)
	if err != nil {
		return fmt.Errorf("expected YYYY-MM-DD: %w", err)
	}
	d.Time = parsed.UTC()
	return nil
}

func (d Date) MarshalYAML() (any, error) {
	return d.Format("2006-01-02"), nil
}

func (d Date) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.Format("2006-01-02"))
}

func Find(start, explicit string) (string, error) {
	if explicit != "" {
		absolute, err := filepath.Abs(explicit)
		if err != nil {
			return "", err
		}
		if _, err := os.Stat(absolute); err != nil {
			return "", err
		}
		return absolute, nil
	}

	current, err := filepath.Abs(start)
	if err != nil {
		return "", err
	}
	if info, statErr := os.Stat(current); statErr == nil && !info.IsDir() {
		current = filepath.Dir(current)
	}
	for {
		candidate := filepath.Join(current, DefaultFilename)
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
		parent := filepath.Dir(current)
		if parent == current || isGitRoot(current) {
			break
		}
		current = parent
	}
	return "", fmt.Errorf("%s not found", DefaultFilename)
}

func LoadProject(path string) (*Project, error) {
	var project Project
	if err := LoadYAMLStrict(path, &project); err != nil {
		return nil, err
	}
	project.Path = path
	project.Root = filepath.Dir(path)
	if project.FailOn == "" {
		project.FailOn = sdk.SeverityError
	}
	if project.Waivers == "" {
		project.Waivers = DefaultWaivers
	}
	if project.Baseline == "" {
		project.Baseline = DefaultBaseline
	}
	if project.Trust == "" {
		project.Trust = DefaultTrust
	}
	if project.Evidence == "" {
		project.Evidence = DefaultEvidence
	}
	if project.Parameters == nil {
		project.Parameters = make(map[string]any)
	}
	project.setBudgetDefaults()
	if err := project.Validate(); err != nil {
		return nil, err
	}
	return &project, nil
}

func (p *Project) Validate() error {
	p.setBudgetDefaults()
	var problems []string
	if p.Version != CurrentVersion {
		problems = append(problems, fmt.Sprintf("version must be %d", CurrentVersion))
	}
	if !projectNamePattern.MatchString(p.Project) {
		problems = append(problems, "project must use lowercase letters, digits, dots, underscores, or hyphens")
	}
	if !p.FailOn.Valid() {
		problems = append(problems, "failOn must be info, warning, or error")
	}
	seenPacks := make(map[string]struct{})
	for i, pack := range p.Packs {
		prefix := fmt.Sprintf("packs[%d]", i)
		if !projectNamePattern.MatchString(pack.Name) {
			problems = append(problems, prefix+".name is invalid")
		}
		if _, exists := seenPacks[pack.Name]; exists {
			problems = append(problems, prefix+" duplicates pack "+pack.Name)
		}
		seenPacks[pack.Name] = struct{}{}
		local := pack.Path != ""
		gitRemote := pack.Git != "" || pack.Ref != "" || pack.Subdir != ""
		ociRemote := pack.OCI != ""
		choices := 0
		if local {
			choices++
		}
		if gitRemote {
			choices++
		}
		if ociRemote {
			choices++
		}
		if choices != 1 {
			problems = append(problems, prefix+" must define exactly one of path, git/ref, or oci")
		}
		if gitRemote && (pack.Git == "" || pack.Ref == "") {
			problems = append(problems, prefix+" requires both git and ref")
		}
		if pack.Git != "" {
			if err := validateGitLocation(pack.Git); err != nil {
				problems = append(problems, prefix+".git: "+err.Error())
			}
		}
		if pack.Ref != "" {
			if strings.TrimSpace(pack.Ref) != pack.Ref || strings.HasPrefix(pack.Ref, "-") || strings.ContainsAny(pack.Ref, "\x00\r\n") {
				problems = append(problems, prefix+".ref is unsafe")
			}
		}
		if err := validateRelativePath(pack.Path); local && err != nil {
			problems = append(problems, prefix+".path: "+err.Error())
		}
		if err := validateRelativePath(pack.Subdir); pack.Subdir != "" && err != nil {
			problems = append(problems, prefix+".subdir: "+err.Error())
		}
		if pack.OCI != "" {
			if err := validateOCIReference(pack.OCI); err != nil {
				problems = append(problems, prefix+".oci: "+err.Error())
			}
		}
	}
	seenRules := make(map[string]struct{})
	for i, rule := range p.Rules {
		if errs := ValidateRule(rule); len(errs) > 0 {
			for _, problem := range errs {
				problems = append(problems, fmt.Sprintf("rules[%d]: %s", i, problem))
			}
		}
		if _, exists := seenRules[rule.ID]; exists {
			problems = append(problems, fmt.Sprintf("rules[%d]: duplicate id %s", i, rule.ID))
		}
		seenRules[rule.ID] = struct{}{}
	}
	if errs := p.validateWorkspaces(seenPacks); len(errs) > 0 {
		problems = append(problems, errs...)
	}
	if p.Budgets.MaximumFiles < 1 || p.Budgets.MaximumDocumentBytes < 1 || p.Budgets.MaximumFindings < 1 {
		problems = append(problems, "budgets file, document-byte, and finding limits must be positive")
	}
	for name, value := range map[string]string{"maximumRuleDuration": p.Budgets.MaximumRuleDuration, "maximumTotalDuration": p.Budgets.MaximumTotalDuration} {
		if duration, err := time.ParseDuration(value); err != nil || duration <= 0 {
			problems = append(problems, "budgets."+name+" must be a positive duration")
		}
	}
	if err := validateRelativePath(p.Waivers); err != nil {
		problems = append(problems, "waivers: "+err.Error())
	}
	if err := validateRelativePath(p.Baseline); err != nil {
		problems = append(problems, "baseline: "+err.Error())
	}
	if err := validateRelativePath(p.Trust); err != nil {
		problems = append(problems, "trust: "+err.Error())
	}
	if err := validateRelativePath(p.Evidence); err != nil {
		problems = append(problems, "evidence: "+err.Error())
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return errors.New(strings.Join(problems, "\n"))
	}
	return nil
}

func (p *Project) setBudgetDefaults() {
	if p.Budgets.MaximumFiles == 0 {
		p.Budgets.MaximumFiles = 100_000
	}
	if p.Budgets.MaximumDocumentBytes == 0 {
		p.Budgets.MaximumDocumentBytes = 16 << 20
	}
	if p.Budgets.MaximumFindings == 0 {
		p.Budgets.MaximumFindings = 10_000
	}
	if p.Budgets.MaximumRuleDuration == "" {
		p.Budgets.MaximumRuleDuration = "30s"
	}
	if p.Budgets.MaximumTotalDuration == "" {
		p.Budgets.MaximumTotalDuration = "2m"
	}
}

func (p *Project) validateWorkspaces(packs map[string]struct{}) []string {
	if len(p.Workspaces) == 0 {
		return nil
	}
	var problems []string
	byName := make(map[string]Workspace, len(p.Workspaces))
	for index, workspace := range p.Workspaces {
		prefix := fmt.Sprintf("workspaces[%d]", index)
		if !projectNamePattern.MatchString(workspace.Name) || workspace.Name == "root" {
			problems = append(problems, prefix+".name is invalid or reserved")
		}
		if _, exists := byName[workspace.Name]; exists {
			problems = append(problems, prefix+" duplicates workspace "+workspace.Name)
		}
		byName[workspace.Name] = workspace
		if len(workspace.Paths) == 0 {
			problems = append(problems, prefix+".paths is required")
		}
		for _, pattern := range workspace.Paths {
			if _, err := repository.Matches("validation-probe", []string{pattern}); err != nil {
				problems = append(problems, prefix+".paths: "+err.Error())
			}
		}
		if strings.TrimSpace(workspace.Owner) == "" {
			problems = append(problems, prefix+".owner is required")
		}
		seen := map[string]bool{}
		for _, name := range workspace.Packs {
			if seen[name] {
				problems = append(problems, prefix+".packs duplicates "+name)
			}
			seen[name] = true
			if _, exists := packs[name]; !exists {
				problems = append(problems, prefix+".packs references unknown pack "+name)
			}
		}
		seen = map[string]bool{}
		for _, name := range workspace.DependsOn {
			if seen[name] {
				problems = append(problems, prefix+".dependsOn duplicates "+name)
			}
			seen[name] = true
		}
	}
	state := map[string]int{}
	var visit func(string, []string)
	visit = func(name string, stack []string) {
		if state[name] == 2 {
			return
		}
		if state[name] == 1 {
			problems = append(problems, "workspace dependency cycle: "+strings.Join(append(stack, name), " -> "))
			return
		}
		workspace, exists := byName[name]
		if !exists {
			return
		}
		state[name] = 1
		for _, dependency := range workspace.DependsOn {
			if _, exists := byName[dependency]; !exists {
				problems = append(problems, "workspace "+name+" depends on unknown workspace "+dependency)
				continue
			}
			visit(dependency, append(stack, name))
		}
		state[name] = 2
	}
	for name := range byName {
		visit(name, nil)
	}
	for _, workspace := range p.Workspaces {
		values := map[string][]byte{}
		visited := map[string]bool{}
		var collect func(string)
		collect = func(name string) {
			if visited[name] {
				return
			}
			visited[name] = true
			dependency, exists := byName[name]
			if !exists {
				return
			}
			for key, value := range dependency.Parameters {
				encoded, _ := json.Marshal(value)
				if previous, exists := values[key]; exists && !bytes.Equal(previous, encoded) {
					problems = append(problems, "workspace "+workspace.Name+" has conflicting dependency parameter "+key)
				} else {
					values[key] = encoded
				}
			}
			for _, nested := range dependency.DependsOn {
				collect(nested)
			}
		}
		for _, dependency := range workspace.DependsOn {
			collect(dependency)
		}
	}
	return problems
}

func ValidateRule(rule sdk.Rule) []string {
	var problems []string
	if !ruleIDPattern.MatchString(rule.ID) {
		problems = append(problems, "id must be lowercase dot/hyphen-separated")
	}
	for field, value := range map[string]string{
		"title":       rule.Title,
		"description": rule.Description,
		"rationale":   rule.Rationale,
		"remediation": rule.Remediation,
		"kind":        rule.Kind,
	} {
		if strings.TrimSpace(value) == "" {
			problems = append(problems, field+" is required")
		}
	}
	if !ruleIDPattern.MatchString(rule.Kind) {
		problems = append(problems, "kind must be lowercase dot/hyphen-separated")
	}
	if !rule.Severity.Valid() {
		problems = append(problems, "severity must be info, warning, or error")
	}
	for _, control := range rule.Controls {
		if strings.TrimSpace(control.Framework) == "" || strings.TrimSpace(control.ID) == "" {
			problems = append(problems, "controls require framework and id")
		}
	}
	for _, dependency := range rule.Dependencies {
		if strings.HasPrefix(dependency, "{{") && strings.HasSuffix(dependency, "}}") {
			continue
		}
		if _, err := repository.Matches("validation-probe", []string{dependency}); err != nil {
			problems = append(problems, "dependencies: "+err.Error())
		}
	}
	sort.Strings(problems)
	return problems
}

func LoadPack(path string) (*Pack, error) {
	manifest := path
	if info, err := os.Stat(path); err == nil && info.IsDir() {
		manifest = filepath.Join(path, "pack.yaml")
	}
	var pack Pack
	if err := LoadYAMLStrict(manifest, &pack); err != nil {
		return nil, err
	}
	if pack.Version != CurrentVersion {
		return nil, fmt.Errorf("%s: version must be %d", manifest, CurrentVersion)
	}
	if !projectNamePattern.MatchString(pack.Name) {
		return nil, fmt.Errorf("%s: invalid pack name", manifest)
	}
	if !semverPattern.MatchString(pack.Release) || strings.TrimSpace(pack.Description) == "" {
		return nil, fmt.Errorf("%s: semantic release and description are required", manifest)
	}
	if pack.Maturity == "" {
		pack.Maturity = "experimental"
	}
	if pack.Maturity != "experimental" && pack.Maturity != "recommended" && pack.Maturity != "stable" {
		return nil, fmt.Errorf("%s: maturity must be experimental, recommended, or stable", manifest)
	}
	if pack.Maturity != "experimental" && (strings.TrimSpace(pack.Owner) == "" || strings.TrimSpace(pack.CompatibilityNotes) == "") {
		return nil, fmt.Errorf("%s: owner and compatibilityNotes are required", manifest)
	}
	if pack.Compatibility.Config != "" {
		if _, err := versionSatisfies(strconv.Itoa(CurrentVersion), pack.Compatibility.Config); err != nil {
			return nil, fmt.Errorf("%s: invalid config compatibility: %w", manifest, err)
		}
	}
	if pack.Compatibility.Hoolicy != "" {
		if _, err := versionSatisfies("0.0.0", pack.Compatibility.Hoolicy); err != nil {
			return nil, fmt.Errorf("%s: invalid Hoolicy compatibility: %w", manifest, err)
		}
	}
	if len(pack.Rules) == 0 {
		return nil, fmt.Errorf("%s: at least one rule is required", manifest)
	}
	for name, parameter := range pack.Parameters {
		if !projectNamePattern.MatchString(name) {
			return nil, fmt.Errorf("%s: invalid parameter name %s", manifest, name)
		}
		if strings.TrimSpace(parameter.Description) == "" || !parameterTypeMatches(parameter.Type, parameter.Default) && parameter.Default != nil {
			return nil, fmt.Errorf("%s: parameter %s needs a description and a valid %s default", manifest, name, parameter.Type)
		}
		if parameter.Type != "string" && parameter.Type != "string_list" && parameter.Type != "bool" && parameter.Type != "number" {
			return nil, fmt.Errorf("%s: parameter %s has unsupported type %s", manifest, name, parameter.Type)
		}
	}
	seen := make(map[string]struct{})
	for i, rule := range pack.Rules {
		if problems := ValidateRule(rule); len(problems) > 0 {
			return nil, fmt.Errorf("%s rules[%d]: %s", manifest, i, strings.Join(problems, "; "))
		}
		if _, exists := seen[rule.ID]; exists {
			return nil, fmt.Errorf("%s: duplicate rule id %s", manifest, rule.ID)
		}
		if !strings.HasPrefix(rule.ID, pack.Name+".") {
			return nil, fmt.Errorf("%s: rule id %s must use pack prefix %s", manifest, rule.ID, pack.Name+".")
		}
		seen[rule.ID] = struct{}{}
	}
	return &pack, nil
}

func ValidatePackCompatibility(pack *Pack, toolVersion string) error {
	if pack.Compatibility.Config != "" {
		ok, err := versionSatisfies(strconv.Itoa(CurrentVersion), pack.Compatibility.Config)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("pack %s requires config %s, engine uses config %d", pack.Name, pack.Compatibility.Config, CurrentVersion)
		}
	}
	if pack.Compatibility.Hoolicy != "" && semverPattern.MatchString(strings.TrimPrefix(toolVersion, "v")) {
		ok, err := versionSatisfies(strings.TrimPrefix(toolVersion, "v"), pack.Compatibility.Hoolicy)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("pack %s requires Hoolicy %s, running %s", pack.Name, pack.Compatibility.Hoolicy, toolVersion)
		}
	}
	return nil
}

func versionSatisfies(version, constraint string) (bool, error) {
	current, err := normalizeRangeVersion(version)
	if err != nil {
		return false, err
	}
	constraint = strings.TrimSpace(constraint)
	if constraint == "" {
		return true, nil
	}
	alternatives := strings.Split(constraint, "||")
	for _, alternative := range alternatives {
		if strings.TrimSpace(alternative) == "" {
			return false, errors.New("empty compatibility range alternative")
		}
	}
	for _, alternative := range alternatives {
		alternative = strings.TrimSpace(alternative)
		ok, err := versionSatisfiesAll(current, alternative)
		if err != nil {
			return false, err
		}
		if ok {
			return true, nil
		}
	}
	return false, nil
}

func versionSatisfiesAll(current, constraint string) (bool, error) {
	for _, token := range strings.Fields(constraint) {
		match := rangeTokenPattern.FindStringSubmatch(token)
		if match == nil {
			return false, fmt.Errorf("unsupported range token %q", token)
		}
		candidate, err := normalizeRangeVersion(match[2])
		if err != nil {
			return false, err
		}
		comparison, err := CompareSemanticVersions(current, candidate)
		if err != nil {
			return false, err
		}
		ok := false
		switch match[1] {
		case "", "=":
			ok = comparison == 0
		case ">":
			ok = comparison > 0
		case ">=":
			ok = comparison >= 0
		case "<":
			ok = comparison < 0
		case "<=":
			ok = comparison <= 0
		}
		if !ok {
			return false, nil
		}
	}
	return true, nil
}

func normalizeRangeVersion(value string) (string, error) {
	if semverPattern.MatchString(value) {
		return value, nil
	}
	parts := strings.Split(value, ".")
	if len(parts) == 0 || len(parts) > 3 {
		return "", fmt.Errorf("invalid version %q", value)
	}
	for len(parts) < 3 {
		parts = append(parts, "0")
	}
	normalized := strings.Join(parts, ".")
	if !semverPattern.MatchString(normalized) {
		return "", fmt.Errorf("invalid version %q", value)
	}
	return normalized, nil
}

func (p *Pack) Instantiate(values map[string]any) ([]sdk.Rule, error) {
	parameters := make(map[string]any, len(p.Parameters))
	for name, definition := range p.Parameters {
		if definition.Default != nil {
			parameters[name] = definition.Default
		}
	}
	for name, value := range values {
		if _, known := p.Parameters[name]; !known {
			return nil, fmt.Errorf("pack %s: unknown parameter %s", p.Name, name)
		}
		parameters[name] = value
	}
	for name, definition := range p.Parameters {
		value, exists := parameters[name]
		if definition.Required && !exists {
			return nil, fmt.Errorf("pack %s: required parameter %s is missing", p.Name, name)
		}
		if exists && !parameterTypeMatches(definition.Type, value) {
			return nil, fmt.Errorf("pack %s: parameter %s must be %s", p.Name, name, definition.Type)
		}
	}

	rules := make([]sdk.Rule, 0, len(p.Rules))
	for _, source := range p.Rules {
		encoded, err := yaml.Marshal(source)
		if err != nil {
			return nil, err
		}
		var raw any
		if err := yaml.Unmarshal(encoded, &raw); err != nil {
			return nil, err
		}
		expanded, err := expandParameters(raw, parameters)
		if err != nil {
			return nil, fmt.Errorf("pack %s rule %s: %w", p.Name, source.ID, err)
		}
		reencoded, err := yaml.Marshal(expanded)
		if err != nil {
			return nil, err
		}
		var rule sdk.Rule
		if err := yaml.Unmarshal(reencoded, &rule); err != nil {
			return nil, err
		}
		rule.Pack = p.Name
		rule.PackVersion = p.Release
		rules = append(rules, rule)
	}
	return rules, nil
}

func LoadLock(path string) (*Lock, error) {
	data, err := readPolicyFile(path)
	if err != nil {
		return nil, err
	}
	var lock Lock
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&lock); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if lock.Version != CurrentVersion {
		return nil, fmt.Errorf("%s: version must be %d", path, CurrentVersion)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("%s: exactly one JSON value is required", path)
		}
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	seen := make(map[string]bool, len(lock.Packs))
	for index, entry := range lock.Packs {
		prefix := fmt.Sprintf("%s packs[%d]", path, index)
		if !projectNamePattern.MatchString(entry.Name) {
			return nil, fmt.Errorf("%s: invalid name", prefix)
		}
		if seen[entry.Name] {
			return nil, fmt.Errorf("%s: duplicate pack %s", path, entry.Name)
		}
		seen[entry.Name] = true
		if (entry.Git == "") == (entry.OCI == "") {
			return nil, fmt.Errorf("%s: exactly one of git or oci is required", prefix)
		}
		if entry.Git != "" {
			if err := validateGitLocation(entry.Git); err != nil {
				return nil, fmt.Errorf("%s git: %w", prefix, err)
			}
			if entry.Ref == "" || strings.TrimSpace(entry.Ref) != entry.Ref || strings.HasPrefix(entry.Ref, "-") || strings.ContainsAny(entry.Ref, "\x00\r\n") {
				return nil, fmt.Errorf("%s: invalid ref", prefix)
			}
			if !commitPattern.MatchString(entry.Commit) {
				return nil, fmt.Errorf("%s: invalid commit", prefix)
			}
		} else {
			if err := validateOCIReference(entry.OCI); err != nil {
				return nil, fmt.Errorf("%s oci: %w", prefix, err)
			}
			if !digestPattern.MatchString(entry.ManifestDigest) || !digestPattern.MatchString(entry.PackDigest) {
				return nil, fmt.Errorf("%s: invalid OCI manifest or pack digest", prefix)
			}
			if strings.TrimSpace(entry.VerifiedBy) == "" {
				return nil, fmt.Errorf("%s: OCI signature verification record is required", prefix)
			}
		}
		if !digestPattern.MatchString(entry.Digest) {
			return nil, fmt.Errorf("%s: invalid digest", prefix)
		}
		if entry.Vendor == "" {
			return nil, fmt.Errorf("%s: vendor path is required", prefix)
		}
		if err := validateRelativePath(entry.Vendor); err != nil {
			return nil, fmt.Errorf("%s vendor: %w", prefix, err)
		}
		if entry.Subdir != "" {
			if err := validateRelativePath(entry.Subdir); err != nil {
				return nil, fmt.Errorf("%s subdir: %w", prefix, err)
			}
		}
		if entry.Release != "" && !semverPattern.MatchString(entry.Release) {
			return nil, fmt.Errorf("%s: invalid release", prefix)
		}
	}
	return &lock, nil
}

func SaveLock(path string, lock Lock) error {
	sort.Slice(lock.Packs, func(i, j int) bool { return lock.Packs[i].Name < lock.Packs[j].Name })
	data, err := json.MarshalIndent(lock, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return atomicWrite(path, data, 0o644)
}

func SaveProject(path string, project Project) error {
	project.Root = ""
	project.Path = ""
	data, err := yaml.Marshal(project)
	if err != nil {
		return err
	}
	return atomicWrite(path, data, 0o644)
}

func SavePack(path string, pack Pack) error {
	data, err := yaml.Marshal(pack)
	if err != nil {
		return err
	}
	return atomicWrite(path, data, 0o644)
}

func SaveWaivers(path string, waivers WaiverFile) error {
	if waivers.Version != CurrentVersion {
		return fmt.Errorf("waiver version must be %d", CurrentVersion)
	}
	sort.Slice(waivers.Waivers, func(i, j int) bool { return waivers.Waivers[i].ID < waivers.Waivers[j].ID })
	data, err := yaml.Marshal(waivers)
	if err != nil {
		return err
	}
	return atomicWrite(path, data, 0o644)
}

func LoadBaseline(path string) (*BaselineFile, error) {
	data, err := readPolicyFile(path)
	if err != nil {
		return nil, err
	}
	var baseline BaselineFile
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&baseline); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("%s: exactly one JSON value is required", path)
		}
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if err := ValidateBaseline(baseline); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &baseline, nil
}

func ValidateBaseline(baseline BaselineFile) error {
	var problems []string
	if baseline.Version != CurrentVersion {
		problems = append(problems, fmt.Sprintf("version must be %d", CurrentVersion))
	}
	if !projectNamePattern.MatchString(baseline.Project) {
		problems = append(problems, "project is invalid")
	}
	if baseline.CreatedAt.IsZero() {
		problems = append(problems, "createdAt is required")
	}
	if strings.TrimSpace(baseline.ToolVersion) == "" {
		problems = append(problems, "toolVersion is required")
	}
	if !digestPattern.MatchString(baseline.PolicyDigest) {
		problems = append(problems, "policyDigest is invalid")
	}
	seen := make(map[string]bool, len(baseline.Entries))
	for index, entry := range baseline.Entries {
		prefix := fmt.Sprintf("entries[%d]", index)
		if !fingerprintPattern.MatchString(entry.Fingerprint) {
			problems = append(problems, prefix+".fingerprint is invalid")
		}
		if seen[entry.Fingerprint] {
			problems = append(problems, prefix+" duplicates fingerprint "+entry.Fingerprint)
		}
		seen[entry.Fingerprint] = true
		if !ruleIDPattern.MatchString(entry.RuleID) || strings.HasPrefix(entry.RuleID, "hoolicy.") {
			problems = append(problems, prefix+".ruleId is invalid")
		}
		if !entry.Severity.Valid() {
			problems = append(problems, prefix+".severity is invalid")
		}
		if !digestPattern.MatchString(entry.PolicyDigest) {
			problems = append(problems, prefix+".policyDigest is invalid")
		}
		if !digestPattern.MatchString(entry.FindingDigest) {
			problems = append(problems, prefix+".findingDigest is invalid")
		}
		if entry.CreatedAt.IsZero() {
			problems = append(problems, prefix+".createdAt is required")
		}
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return errors.New(strings.Join(problems, "; "))
	}
	return nil
}

func SaveBaseline(path string, baseline BaselineFile) error {
	sort.Slice(baseline.Entries, func(i, j int) bool {
		if baseline.Entries[i].RuleID != baseline.Entries[j].RuleID {
			return baseline.Entries[i].RuleID < baseline.Entries[j].RuleID
		}
		return baseline.Entries[i].Fingerprint < baseline.Entries[j].Fingerprint
	})
	if err := ValidateBaseline(baseline); err != nil {
		return err
	}
	data, err := json.MarshalIndent(baseline, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(path, append(data, '\n'), 0o644)
}

func LoadWaivers(path string) (*WaiverFile, error) {
	var waivers WaiverFile
	if err := LoadYAMLStrict(path, &waivers); err != nil {
		return nil, err
	}
	if waivers.Version != CurrentVersion {
		return nil, fmt.Errorf("%s: version must be %d", path, CurrentVersion)
	}
	return &waivers, nil
}

func LoadTrust(path string) (*TrustPolicy, error) {
	var trust TrustPolicy
	if err := LoadYAMLStrict(path, &trust); err != nil {
		return nil, err
	}
	if trust.Version != CurrentVersion {
		return nil, fmt.Errorf("%s: version must be %d", path, CurrentVersion)
	}
	if len(trust.Requirements) == 0 {
		return nil, fmt.Errorf("%s: at least one trust requirement is required", path)
	}
	seen := make(map[string]bool)
	for index, requirement := range trust.Requirements {
		prefix := fmt.Sprintf("%s requirements[%d]", path, index)
		if !projectNamePattern.MatchString(requirement.Name) || seen[requirement.Name] {
			return nil, fmt.Errorf("%s: unique valid name is required", prefix)
		}
		seen[requirement.Name] = true
		if requirement.Registry == "" || requirement.Registry == "*" || strings.ContainsAny(requirement.Registry, "\x00\r\n") {
			return nil, fmt.Errorf("%s: narrow registry pattern is required", prefix)
		}
		keyMode := requirement.Key != ""
		identityMode := requirement.Identity != "" || requirement.Issuer != ""
		if keyMode == identityMode || identityMode && (requirement.Identity == "" || requirement.Issuer == "") {
			return nil, fmt.Errorf("%s: exactly one key or identity plus issuer is required", prefix)
		}
		if keyMode {
			if err := validateRelativePath(requirement.Key); err != nil {
				return nil, fmt.Errorf("%s key: %w", prefix, err)
			}
		}
	}
	return &trust, nil
}

func LoadCatalog(path string) (*Catalog, error) {
	var catalog Catalog
	if err := loadStrictJSON(path, &catalog); err != nil {
		return nil, err
	}
	if catalog.Version != CurrentVersion || !projectNamePattern.MatchString(catalog.Name) || catalog.GeneratedAt.IsZero() || len(catalog.Packs) == 0 {
		return nil, fmt.Errorf("%s: version, name, generatedAt, and packs are required", path)
	}
	seen := make(map[string]bool)
	for index, entry := range catalog.Packs {
		if !projectNamePattern.MatchString(entry.Name) || !semverPattern.MatchString(entry.Release) || validateOCIReference(entry.OCI) != nil {
			return nil, fmt.Errorf("%s packs[%d]: invalid name, release, or OCI coordinate", path, index)
		}
		key := entry.Name + "@" + entry.Release
		if seen[key] {
			return nil, fmt.Errorf("%s: duplicate catalog entry %s", path, key)
		}
		seen[key] = true
	}
	return &catalog, nil
}

func LoadCatalogLock(path string) (*CatalogLock, error) {
	var lock CatalogLock
	if err := loadStrictJSON(path, &lock); err != nil {
		return nil, err
	}
	if lock.Version != CurrentVersion || validateOCIReference(lock.Source) != nil || !digestPattern.MatchString(lock.ManifestDigest) || !digestPattern.MatchString(lock.CatalogDigest) || strings.TrimSpace(lock.VerifiedBy) == "" {
		return nil, fmt.Errorf("%s: invalid signed catalog acquisition record", path)
	}
	return &lock, nil
}

func SaveCatalogLock(path string, lock CatalogLock) error {
	data, err := json.MarshalIndent(lock, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(path, append(data, '\n'), 0o644)
}

func loadStrictJSON(path string, target any) error {
	data, err := readPolicyFile(path)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("%s: exactly one JSON value is required", path)
		}
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

func LoadYAMLStrict(path string, target any) error {
	data, err := readPolicyFile(path)
	if err != nil {
		return err
	}
	var node yaml.Node
	if err := yaml.Unmarshal(data, &node); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if err := uniqueMappingKeys(&node); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("%s: exactly one YAML document is required", path)
		}
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

func readPolicyFile(path string) ([]byte, error) {
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if pathInfo.Mode()&os.ModeSymlink != 0 || !pathInfo.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: expected a regular file, symbolic links are forbidden", path)
	}
	if pathInfo.Size() > maxPolicyInputBytes {
		return nil, fmt.Errorf("%s: policy input exceeds %d bytes", path, maxPolicyInputBytes)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(opened, pathInfo) || opened.Size() > maxPolicyInputBytes {
		return nil, fmt.Errorf("%s: policy input changed, is not regular, or exceeds %d bytes", path, maxPolicyInputBytes)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxPolicyInputBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxPolicyInputBytes {
		return nil, fmt.Errorf("%s: policy input exceeds %d bytes", path, maxPolicyInputBytes)
	}
	return data, nil
}

func uniqueMappingKeys(node *yaml.Node) error {
	if node == nil {
		return nil
	}
	if node.Kind == yaml.MappingNode {
		seen := make(map[string]yaml.Node)
		for i := 0; i+1 < len(node.Content); i += 2 {
			key := node.Content[i]
			if previous, exists := seen[key.Value]; exists {
				return fmt.Errorf("duplicate key %q at %d:%d (first at %d:%d)", key.Value, key.Line, key.Column, previous.Line, previous.Column)
			}
			seen[key.Value] = *key
		}
	}
	for _, child := range node.Content {
		if err := uniqueMappingKeys(child); err != nil {
			return err
		}
	}
	return nil
}

func parameterTypeMatches(kind string, value any) bool {
	switch kind {
	case "string":
		_, ok := value.(string)
		return ok
	case "string_list":
		switch values := value.(type) {
		case []string:
			return true
		case []any:
			for _, entry := range values {
				if _, ok := entry.(string); !ok {
					return false
				}
			}
			return true
		default:
			return false
		}
	case "bool":
		_, ok := value.(bool)
		return ok
	case "number":
		switch value.(type) {
		case int, int64, uint64, float64:
			return true
		default:
			return false
		}
	default:
		return false
	}
}

func expandParameters(value any, parameters map[string]any) (any, error) {
	switch current := value.(type) {
	case string:
		if strings.HasPrefix(current, "{{") && strings.HasSuffix(current, "}}") {
			name := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(current, "{{"), "}}"))
			parameter, exists := parameters[name]
			if !exists {
				return nil, fmt.Errorf("parameter %s is not set", name)
			}
			return parameter, nil
		}
		return current, nil
	case []any:
		result := make([]any, 0, len(current))
		for _, entry := range current {
			expanded, err := expandParameters(entry, parameters)
			if err != nil {
				return nil, err
			}
			if text, exactParameter := entry.(string); exactParameter && strings.HasPrefix(text, "{{") && strings.HasSuffix(text, "}}") {
				switch list := expanded.(type) {
				case []any:
					result = append(result, list...)
					continue
				case []string:
					for _, item := range list {
						result = append(result, item)
					}
					continue
				}
			}
			result = append(result, expanded)
		}
		return result, nil
	case map[string]any:
		result := make(map[string]any, len(current))
		for key, entry := range current {
			expanded, err := expandParameters(entry, parameters)
			if err != nil {
				return nil, err
			}
			result[key] = expanded
		}
		return result, nil
	case map[any]any:
		result := make(map[string]any, len(current))
		for key, entry := range current {
			keyString, ok := key.(string)
			if !ok {
				return nil, fmt.Errorf("non-string map key")
			}
			expanded, err := expandParameters(entry, parameters)
			if err != nil {
				return nil, err
			}
			result[keyString] = expanded
		}
		return result, nil
	default:
		return value, nil
	}
}

func ValidateWaiver(waiver Waiver, now time.Time) error {
	return ValidateWaiverForProject(waiver, now, false)
}

func ValidateWaiverForProject(waiver Waiver, now time.Time, requireApprover bool) error {
	var problems []string
	if !ruleIDPattern.MatchString(waiver.ID) {
		problems = append(problems, "id is invalid")
	}
	if !ruleIDPattern.MatchString(waiver.Rule) {
		problems = append(problems, "rule is invalid")
	}
	if len(waiver.Fingerprints) == 0 && len(waiver.Paths) == 0 {
		problems = append(problems, "at least one fingerprint or path is required")
	}
	for _, fingerprint := range waiver.Fingerprints {
		if !fingerprintPattern.MatchString(fingerprint) {
			problems = append(problems, "fingerprint must contain exactly 64 lowercase hexadecimal characters")
		}
	}
	for _, path := range waiver.Paths {
		cleaned := strings.TrimSpace(filepath.ToSlash(path))
		if cleaned == "" || cleaned == "*" || cleaned == "**" || cleaned == "**/*" || cleaned == "." {
			problems = append(problems, "global path scopes are forbidden")
			continue
		}
		if err := validateRelativePath(path); err != nil {
			problems = append(problems, "path "+path+": "+err.Error())
			continue
		}
		if err := validateWaiverPathPattern(path); err != nil {
			problems = append(problems, "path "+path+": "+err.Error())
		}
	}
	if len(strings.TrimSpace(waiver.Reason)) < 20 {
		problems = append(problems, "reason must contain at least 20 characters")
	}
	if strings.TrimSpace(waiver.Owner) == "" {
		problems = append(problems, "owner is required")
	}
	if requireApprover && strings.TrimSpace(waiver.Approver) == "" {
		problems = append(problems, "approver is required by project policy")
	}
	parsedTicket, err := url.Parse(waiver.Ticket)
	if err != nil || parsedTicket.Scheme != "https" || parsedTicket.Host == "" {
		problems = append(problems, "ticket must be an absolute HTTPS URL")
	}
	if waiver.Created.IsZero() || waiver.Expires.IsZero() {
		problems = append(problems, "created and expires are required")
	} else {
		if waiver.Expires.Before(waiver.Created.Time) {
			problems = append(problems, "expires must not precede created")
		}
		if waiver.Expires.Sub(waiver.Created.Time) > 90*24*time.Hour {
			problems = append(problems, "waiver lifetime exceeds 90 days")
		}
		if now.UTC().Truncate(24 * time.Hour).After(waiver.Expires.Time) {
			problems = append(problems, "waiver is expired")
		}
	}
	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "; "))
	}
	return nil
}

func validateWaiverPathPattern(pattern string) error {
	rootProbes := []string{"README.md", ".hidden", "policy.json"}
	nestedProbes := []string{"docs/guide.md", "src/main.go", ".github/workflows/ci.yml"}
	allMatch := func(probes []string) (bool, error) {
		for _, probe := range probes {
			matched, err := repository.Matches(probe, []string{pattern})
			if err != nil {
				return false, err
			}
			if !matched {
				return false, nil
			}
		}
		return true, nil
	}
	rootGlobal, err := allMatch(rootProbes)
	if err != nil {
		return fmt.Errorf("invalid glob: %w", err)
	}
	nestedGlobal, err := allMatch(nestedProbes)
	if err != nil {
		return fmt.Errorf("invalid glob: %w", err)
	}
	if rootGlobal || nestedGlobal {
		return errors.New("global path scopes are forbidden")
	}
	return nil
}

func validateRelativePath(path string) error {
	if path == "" {
		return nil
	}
	if strings.TrimSpace(path) != path || strings.ContainsAny(path, "\\\x00") {
		return errors.New("path contains unsafe whitespace or NUL")
	}
	if filepath.IsAbs(path) || portableWindowsVolume(path) {
		return errors.New("absolute paths are forbidden")
	}
	clean := filepath.Clean(filepath.FromSlash(path))
	if clean == "." {
		return errors.New("path must name a file or subdirectory")
	}
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return errors.New("path escapes repository root")
	}
	return nil
}

func portableWindowsVolume(path string) bool {
	return len(path) >= 2 && path[1] == ':' && (path[0] >= 'A' && path[0] <= 'Z' || path[0] >= 'a' && path[0] <= 'z')
}

func validateGitLocation(value string) error {
	if value == "" {
		return errors.New("location is required")
	}
	if strings.TrimSpace(value) != value || strings.HasPrefix(value, "-") || strings.ContainsAny(value, "\x00\r\n") {
		return errors.New("location is unsafe")
	}
	if strings.Contains(value, "://") {
		parsed, err := url.Parse(value)
		if err != nil || parsed.Scheme == "" {
			return errors.New("location is invalid")
		}
		if parsed.RawQuery != "" || parsed.Fragment != "" {
			return errors.New("query strings and fragments are forbidden")
		}
		if parsed.User != nil {
			_, hasPassword := parsed.User.Password()
			if hasPassword || parsed.Scheme == "http" || parsed.Scheme == "https" {
				return errors.New("embedded credentials are forbidden")
			}
		}
	}
	return nil
}

func validateOCIReference(value string) error {
	if strings.TrimSpace(value) != value || strings.HasPrefix(value, "-") || strings.ContainsAny(value, "\x00\r\n?#") || strings.Contains(value, "://") {
		return errors.New("reference is unsafe")
	}
	slash := strings.IndexByte(value, '/')
	if slash <= 0 || slash == len(value)-1 {
		return errors.New("reference must include registry and repository")
	}
	registry := value[:slash]
	if strings.Contains(registry, "@") || !ociRegistryPattern.MatchString(registry) {
		return errors.New("registry is invalid or contains credentials")
	}
	repository := value[slash+1:]
	lastSlash := strings.LastIndexByte(repository, '/')
	leaf := repository[lastSlash+1:]
	if at := strings.LastIndexByte(leaf, '@'); at >= 0 {
		if !digestPattern.MatchString(leaf[at+1:]) {
			return errors.New("digest reference is invalid")
		}
		leaf = leaf[:at]
	} else if colon := strings.LastIndexByte(leaf, ':'); colon <= 0 || colon == len(leaf)-1 {
		return errors.New("reference must use an explicit tag or digest")
	} else if !ociTagPattern.MatchString(leaf[colon+1:]) {
		return errors.New("tag is invalid")
	} else {
		leaf = leaf[:colon]
	}
	repositoryWithoutVersion := repository[:len(repository)-len(repository[lastSlash+1:])] + leaf
	if !ociRepositoryPattern.MatchString(repositoryWithoutVersion) {
		return errors.New("repository name is invalid")
	}
	return nil
}

func ValidateOCIReference(value string) error { return validateOCIReference(value) }

// CompareSemanticVersions returns -1, 0, or 1 using SemVer precedence. Build
// metadata is ignored; numeric prerelease identifiers sort before text.
func CompareSemanticVersions(left, right string) (int, error) {
	if !semverPattern.MatchString(left) || !semverPattern.MatchString(right) {
		return 0, errors.New("invalid semantic version")
	}
	parse := func(value string) ([3]int, []string) {
		withoutBuild := strings.SplitN(value, "+", 2)[0]
		parts := strings.SplitN(withoutBuild, "-", 2)
		core := strings.Split(parts[0], ".")
		var numbers [3]int
		for index := range numbers {
			numbers[index], _ = strconv.Atoi(core[index])
		}
		if len(parts) == 2 {
			return numbers, strings.Split(parts[1], ".")
		}
		return numbers, nil
	}
	leftCore, leftPre := parse(left)
	rightCore, rightPre := parse(right)
	for index := range leftCore {
		if leftCore[index] < rightCore[index] {
			return -1, nil
		}
		if leftCore[index] > rightCore[index] {
			return 1, nil
		}
	}
	if len(leftPre) == 0 && len(rightPre) == 0 {
		return 0, nil
	}
	if len(leftPre) == 0 {
		return 1, nil
	}
	if len(rightPre) == 0 {
		return -1, nil
	}
	limit := len(leftPre)
	if len(rightPre) < limit {
		limit = len(rightPre)
	}
	for index := range limit {
		leftNumber, leftErr := strconv.ParseUint(leftPre[index], 10, 64)
		rightNumber, rightErr := strconv.ParseUint(rightPre[index], 10, 64)
		switch {
		case leftErr == nil && rightErr == nil && leftNumber < rightNumber:
			return -1, nil
		case leftErr == nil && rightErr == nil && leftNumber > rightNumber:
			return 1, nil
		case leftErr == nil && rightErr != nil:
			return -1, nil
		case leftErr != nil && rightErr == nil:
			return 1, nil
		case leftPre[index] < rightPre[index]:
			return -1, nil
		case leftPre[index] > rightPre[index]:
			return 1, nil
		}
	}
	if len(leftPre) < len(rightPre) {
		return -1, nil
	}
	if len(leftPre) > len(rightPre) {
		return 1, nil
	}
	return 0, nil
}

func isGitRoot(path string) bool {
	_, err := os.Stat(filepath.Join(path, ".git"))
	return err == nil
}

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".hoolicy-write-*")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(mode); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryName, path)
}
