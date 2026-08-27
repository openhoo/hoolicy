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
	"strings"
	"time"

	"github.com/openhoo/hoolicy/internal/repository"
	"github.com/openhoo/hoolicy/sdk"
	"go.yaml.in/yaml/v3"
)

const (
	CurrentVersion  = 1
	DefaultFilename = "hoolicy.yaml"
	DefaultLockfile = "hoolicy.lock"
	DefaultWaivers  = ".hoolicy/waivers.yaml"
)

var (
	projectNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)
	ruleIDPattern      = regexp.MustCompile(`^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$`)
	fingerprintPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
	commitPattern      = regexp.MustCompile(`^[0-9a-f]{40}$`)
	digestPattern      = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	semverPattern      = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`)
)

type Project struct {
	Version    int            `yaml:"version" json:"version"`
	Project    string         `yaml:"project" json:"project"`
	FailOn     sdk.Severity   `yaml:"failOn,omitempty" json:"failOn,omitempty"`
	Waivers    string         `yaml:"waivers,omitempty" json:"waivers,omitempty"`
	Parameters map[string]any `yaml:"parameters,omitempty" json:"parameters,omitempty"`
	Packs      []PackRef      `yaml:"packs,omitempty" json:"packs,omitempty"`
	Rules      []sdk.Rule     `yaml:"rules,omitempty" json:"rules,omitempty"`
	Root       string         `yaml:"-" json:"-"`
	Path       string         `yaml:"-" json:"-"`
}

type PackRef struct {
	Name   string         `yaml:"name" json:"name"`
	Path   string         `yaml:"path,omitempty" json:"path,omitempty"`
	Git    string         `yaml:"git,omitempty" json:"git,omitempty"`
	Ref    string         `yaml:"ref,omitempty" json:"ref,omitempty"`
	Subdir string         `yaml:"subdir,omitempty" json:"subdir,omitempty"`
	With   map[string]any `yaml:"with,omitempty" json:"with,omitempty"`
}

type Parameter struct {
	Type        string `yaml:"type" json:"type"`
	Required    bool   `yaml:"required,omitempty" json:"required,omitempty"`
	Description string `yaml:"description" json:"description"`
	Default     any    `yaml:"default,omitempty" json:"default,omitempty"`
}

type Pack struct {
	Version     int                  `yaml:"version" json:"version"`
	Name        string               `yaml:"name" json:"name"`
	Release     string               `yaml:"release" json:"release"`
	Description string               `yaml:"description" json:"description"`
	Parameters  map[string]Parameter `yaml:"parameters,omitempty" json:"parameters,omitempty"`
	Rules       []sdk.Rule           `yaml:"rules" json:"rules"`
}

type Lock struct {
	Version int          `json:"version"`
	Packs   []LockedPack `json:"packs"`
}

type LockedPack struct {
	Name    string `json:"name"`
	Git     string `json:"git"`
	Ref     string `json:"ref"`
	Subdir  string `json:"subdir,omitempty"`
	Commit  string `json:"commit"`
	Digest  string `json:"digest"`
	Vendor  string `json:"vendor"`
	Release string `json:"release,omitempty"`
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
	Created      Date     `yaml:"created" json:"created"`
	Expires      Date     `yaml:"expires" json:"expires"`
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
	if project.Parameters == nil {
		project.Parameters = make(map[string]any)
	}
	if err := project.Validate(); err != nil {
		return nil, err
	}
	return &project, nil
}

func (p *Project) Validate() error {
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
		remote := pack.Git != "" || pack.Ref != "" || pack.Subdir != ""
		if local == remote {
			problems = append(problems, prefix+" must define exactly one of path or git/ref")
		}
		if remote && (pack.Git == "" || pack.Ref == "") {
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
	if err := validateRelativePath(p.Waivers); err != nil {
		problems = append(problems, "waivers: "+err.Error())
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return errors.New(strings.Join(problems, "\n"))
	}
	return nil
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
	if err := requireRegularFile(path); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
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
		if err := validateGitLocation(entry.Git); err != nil {
			return nil, fmt.Errorf("%s git: %w", prefix, err)
		}
		if entry.Ref == "" || strings.TrimSpace(entry.Ref) != entry.Ref || strings.HasPrefix(entry.Ref, "-") || strings.ContainsAny(entry.Ref, "\x00\r\n") {
			return nil, fmt.Errorf("%s: invalid ref", prefix)
		}
		if !commitPattern.MatchString(entry.Commit) {
			return nil, fmt.Errorf("%s: invalid commit", prefix)
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

func SaveWaivers(path string, waivers WaiverFile) error {
	data, err := yaml.Marshal(waivers)
	if err != nil {
		return err
	}
	return atomicWrite(path, data, 0o644)
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

func LoadYAMLStrict(path string, target any) error {
	if err := requireRegularFile(path); err != nil {
		return err
	}
	data, err := os.ReadFile(path)
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

func requireRegularFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("%s: expected a regular file, symbolic links are forbidden", path)
	}
	return nil
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
		result := make([]any, len(current))
		for i, entry := range current {
			expanded, err := expandParameters(entry, parameters)
			if err != nil {
				return nil, err
			}
			result[i] = expanded
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
	if strings.TrimSpace(path) != path || strings.ContainsRune(path, '\x00') {
		return errors.New("path contains unsafe whitespace or NUL")
	}
	if filepath.IsAbs(path) {
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
