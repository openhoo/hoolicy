// Package sdk defines Hoolicy's compile-time extension API.
//
// Hoolicy v0.x may evolve this API. Runtime-loaded plugins are intentionally
// unsupported: custom rule kinds are registered while building a binary.
package sdk

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

var kindNamePattern = regexp.MustCompile(`^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$`)

type Severity string

const (
	SeverityInfo    Severity = "info"
	SeverityWarning Severity = "warning"
	SeverityError   Severity = "error"
)

func (s Severity) Valid() bool {
	return s == SeverityInfo || s == SeverityWarning || s == SeverityError
}

func (s Severity) Rank() int {
	switch s {
	case SeverityInfo:
		return 1
	case SeverityWarning:
		return 2
	case SeverityError:
		return 3
	default:
		return 0
	}
}

type Control struct {
	Framework string `json:"framework" yaml:"framework"`
	ID        string `json:"id" yaml:"id"`
}

type Rule struct {
	ID           string         `json:"id" yaml:"id"`
	Title        string         `json:"title" yaml:"title"`
	Description  string         `json:"description" yaml:"description"`
	Rationale    string         `json:"rationale" yaml:"rationale"`
	Remediation  string         `json:"remediation" yaml:"remediation"`
	Severity     Severity       `json:"severity" yaml:"severity"`
	Kind         string         `json:"kind" yaml:"kind"`
	Files        []string       `json:"files,omitempty" yaml:"files,omitempty"`
	Exclude      []string       `json:"exclude,omitempty" yaml:"exclude,omitempty"`
	Dependencies []string       `json:"dependencies,omitempty" yaml:"dependencies,omitempty"`
	Controls     []Control      `json:"controls,omitempty" yaml:"controls,omitempty"`
	Spec         map[string]any `json:"spec,omitempty" yaml:"spec,omitempty"`
	Pack         string         `json:"pack,omitempty" yaml:"-"`
	PackVersion  string         `json:"packVersion,omitempty" yaml:"-"`
}

type Location struct {
	Path   string `json:"path,omitempty"`
	Line   int    `json:"line,omitempty"`
	Column int    `json:"column,omitempty"`
}

type Edit struct {
	Path           string `json:"path"`
	ExpectedSHA256 string `json:"expectedSha256"`
	Start          int    `json:"start"`
	End            int    `json:"end"`
	Replacement    []byte `json:"-"`
	Description    string `json:"description"`
}

type Fix struct {
	Description string `json:"description"`
	Edits       []Edit `json:"edits"`
}

type Finding struct {
	RuleID        string         `json:"ruleId"`
	Title         string         `json:"title"`
	Message       string         `json:"message"`
	Remediation   string         `json:"remediation"`
	Severity      Severity       `json:"severity"`
	Location      Location       `json:"location,omitempty"`
	Workspace     string         `json:"workspace,omitempty"`
	Owner         string         `json:"owner,omitempty"`
	Key           string         `json:"key,omitempty"`
	Fingerprint   string         `json:"fingerprint"`
	PolicyDigest  string         `json:"policyDigest"`
	FindingDigest string         `json:"findingDigest"`
	State         FindingState   `json:"state"`
	StateSource   string         `json:"stateSource,omitempty"`
	Controls      []Control      `json:"controls,omitempty"`
	Pack          string         `json:"pack,omitempty"`
	Waived        bool           `json:"waived,omitempty"`
	WaiverID      string         `json:"waiverId,omitempty"`
	Fix           *Fix           `json:"fix,omitempty"`
	Properties    map[string]any `json:"properties,omitempty"`
}

type FindingState string

const (
	FindingNew      FindingState = "new"
	FindingExisting FindingState = "existing"
	FindingWaived   FindingState = "waived"
)

func (f *Finding) Finalize(rule Rule) {
	f.RuleID = rule.ID
	f.Title = rule.Title
	f.Remediation = rule.Remediation
	f.Severity = rule.Severity
	f.Controls = append([]Control(nil), rule.Controls...)
	f.Pack = rule.Pack
	h := sha256.Sum256([]byte(strings.Join([]string{
		f.RuleID,
		f.Workspace,
		filepath.ToSlash(filepath.Clean(f.Location.Path)),
		fmt.Sprintf("%d:%d", f.Location.Line, f.Location.Column),
		f.Key,
	}, "\x00")))
	f.Fingerprint = hex.EncodeToString(h[:])
	f.PolicyDigest = RuleDigest(rule)
	f.FindingDigest = findingDigest(*f)
	f.State = FindingNew
}

// RuleDigest identifies the complete policy decision contract for one rule.
// It deliberately includes severity and remediation so a baseline cannot hide
// a materially changed rule behind a stable finding fingerprint.
func RuleDigest(rule Rule) string {
	data, _ := json.Marshal(rule)
	hash := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(hash[:])
}

func findingDigest(finding Finding) string {
	data, _ := json.Marshal(struct {
		RuleID      string         `json:"ruleId"`
		Message     string         `json:"message"`
		Remediation string         `json:"remediation"`
		Severity    Severity       `json:"severity"`
		Location    Location       `json:"location"`
		Workspace   string         `json:"workspace,omitempty"`
		Owner       string         `json:"owner,omitempty"`
		Key         string         `json:"key"`
		Properties  map[string]any `json:"properties,omitempty"`
	}{finding.RuleID, finding.Message, finding.Remediation, finding.Severity, finding.Location, finding.Workspace, finding.Owner, finding.Key, finding.Properties})
	hash := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(hash[:])
}

type File struct {
	Path string
	Mode fs.FileMode
	Data []byte
}

func (f File) SHA256() string {
	h := sha256.Sum256(f.Data)
	return hex.EncodeToString(h[:])
}

type GitContext struct {
	Branch            string         `json:"branch"`
	Commit            string         `json:"commit"`
	CommitSubjects    []Commit       `json:"commits"`
	MergeRequestTitle string         `json:"mergeRequestTitle"`
	Dirty             bool           `json:"dirty"`
	Properties        map[string]any `json:"properties,omitempty"`
}

type Commit struct {
	SHA     string `json:"sha"`
	Subject string `json:"subject"`
}

type Repository interface {
	Root() string
	AllFiles() []File
	Match(include, exclude []string) ([]File, error)
	Read(path string) (File, error)
	Git() GitContext
}

type EvalContext struct {
	Repository Repository
	Now        time.Time
	Parameters map[string]any
	Metrics    *EvaluationMetrics
}

type EvaluationMetrics struct {
	ParseCacheHits int
	CELCost        uint64
}

type RuleKind interface {
	Validate(rule Rule) error
	Evaluate(ctx context.Context, input EvalContext, rule Rule) ([]Finding, error)
}

type Fixer interface {
	Fix(ctx context.Context, input EvalContext, rule Rule, finding Finding) (*Fix, error)
}

type Registry struct {
	kinds map[string]RuleKind
}

func NewRegistry() *Registry {
	return &Registry{kinds: make(map[string]RuleKind)}
}

func (r *Registry) Register(name string, kind RuleKind) error {
	if !kindNamePattern.MatchString(name) {
		return fmt.Errorf("rule kind name must be lowercase dot/hyphen-separated")
	}
	if kind == nil {
		return fmt.Errorf("rule kind implementation is required")
	}
	if _, exists := r.kinds[name]; exists {
		return fmt.Errorf("rule kind %q is already registered", name)
	}
	r.kinds[name] = kind
	return nil
}

func (r *Registry) Kind(name string) (RuleKind, bool) {
	kind, ok := r.kinds[name]
	return kind, ok
}

func (r *Registry) Names() []string {
	names := make([]string, 0, len(r.kinds))
	for name := range r.kinds {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
