package evidence

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/openhoo/hoolicy/internal/config"
	"github.com/openhoo/hoolicy/internal/engine"
	"github.com/openhoo/hoolicy/internal/safepath"
	"github.com/openhoo/hoolicy/sdk"
)

type Policy struct {
	Version  int            `yaml:"version" json:"version"`
	External []ExternalSpec `yaml:"external,omitempty" json:"external,omitempty"`
}

type ExternalSpec struct {
	ID               string `yaml:"id" json:"id"`
	Type             string `yaml:"type" json:"type"`
	Path             string `yaml:"path" json:"path"`
	SHA256           string `yaml:"sha256" json:"sha256"`
	SubjectDigest    string `yaml:"subjectDigest" json:"subjectDigest"`
	RequiredProducer string `yaml:"requiredProducer,omitempty" json:"requiredProducer,omitempty"`
	MaximumAge       string `yaml:"maximumAge,omitempty" json:"maximumAge,omitempty"`
	MinimumItems     int    `yaml:"minimumItems,omitempty" json:"minimumItems,omitempty"`
	MaximumFailures  int    `yaml:"maximumFailures,omitempty" json:"maximumFailures,omitempty"`
}

type ExternalRecord struct {
	ID            string         `json:"id"`
	Type          string         `json:"type"`
	Path          string         `json:"path"`
	Digest        string         `json:"digest"`
	SubjectDigest string         `json:"subjectDigest"`
	GeneratedAt   time.Time      `json:"generatedAt,omitempty"`
	Metrics       map[string]int `json:"metrics"`
	Verified      bool           `json:"verified"`
}

type Bundle struct {
	Version      int                 `json:"version"`
	CreatedAt    time.Time           `json:"createdAt"`
	Tool         engine.Tool         `json:"tool"`
	Project      string              `json:"project"`
	Revision     string              `json:"revision"`
	Dirty        bool                `json:"dirty"`
	ConfigDigest string              `json:"configDigest"`
	PolicyDigest string              `json:"policyDigest"`
	Packs        []config.LockedPack `json:"packs"`
	Rules        []RuleRecord        `json:"rules"`
	Decision     *engine.Report      `json:"decision"`
	Controls     []ControlRecord     `json:"controls"`
	Waivers      []config.Waiver     `json:"waivers"`
	External     []ExternalRecord    `json:"external"`
}

type RuleRecord struct {
	ID          string `json:"id"`
	Digest      string `json:"digest"`
	Pack        string `json:"pack,omitempty"`
	PackVersion string `json:"packVersion,omitempty"`
}
type ControlRecord struct {
	Framework string `json:"framework,omitempty"`
	ID        string `json:"id,omitempty"`
	RuleID    string `json:"ruleId"`
	Status    string `json:"status"`
}

const MaxEvidenceFileSize int64 = 64 << 20

var exactSHA256 = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var exactGitRevision = regexp.MustCompile(`^[0-9a-f]{40}(?:[0-9a-f]{24})?$`)
var exactFingerprint = regexp.MustCompile(`^[0-9a-f]{64}$`)

func LoadPolicy(project *config.Project) (*Policy, error) {
	_, path, err := safepath.Existing(project.Root, project.Evidence)
	if errors.Is(err, os.ErrNotExist) {
		return &Policy{Version: config.CurrentVersion, External: []ExternalSpec{}}, nil
	}
	if err != nil {
		return nil, err
	}
	var policy Policy
	if err := config.LoadYAMLStrict(path, &policy); err != nil {
		return nil, err
	}
	if policy.Version != config.CurrentVersion {
		return nil, fmt.Errorf("%s: version must be %d", path, config.CurrentVersion)
	}
	seen := make(map[string]bool)
	for index, spec := range policy.External {
		if spec.ID == "" || seen[spec.ID] {
			return nil, fmt.Errorf("external[%d]: unique id is required", index)
		}
		seen[spec.ID] = true
		if !supportedType(spec.Type) {
			return nil, fmt.Errorf("external %s: unsupported type %s", spec.ID, spec.Type)
		}
		if spec.Path == "" || spec.SHA256 == "" || spec.SubjectDigest == "" {
			return nil, fmt.Errorf("external %s: path, sha256, and subjectDigest are required", spec.ID)
		}
		if !exactSHA256.MatchString(spec.SHA256) || !exactSHA256.MatchString(spec.SubjectDigest) {
			return nil, fmt.Errorf("external %s: digests must be exact SHA-256 values", spec.ID)
		}
		if strings.ContainsAny(spec.RequiredProducer, "\x00\r\n") {
			return nil, fmt.Errorf("external %s: requiredProducer is invalid", spec.ID)
		}
		if spec.MinimumItems < 0 || spec.MaximumFailures < 0 {
			return nil, fmt.Errorf("external %s: thresholds must not be negative", spec.ID)
		}
		if spec.MaximumAge != "" {
			duration, err := time.ParseDuration(spec.MaximumAge)
			if err != nil || duration <= 0 {
				return nil, fmt.Errorf("external %s: maximumAge must be a positive duration", spec.ID)
			}
		}
	}
	return &policy, nil
}

func Build(project *config.Project, report *engine.Report, rules []sdk.Rule) (*Bundle, error) {
	if !exactGitRevision.MatchString(report.Git.Commit) {
		return nil, errors.New("evidence requires an exact repository revision")
	}
	policy, err := LoadPolicy(project)
	if err != nil {
		return nil, err
	}
	external := make([]ExternalRecord, 0, len(policy.External))
	for _, spec := range policy.External {
		record, err := inspectExternal(project.Root, spec, report.GeneratedAt)
		if err != nil {
			return nil, fmt.Errorf("external evidence %s: %w", spec.ID, err)
		}
		external = append(external, record)
	}
	var locked []config.LockedPack
	if lock, err := config.LoadLock(filepath.Join(project.Root, config.DefaultLockfile)); err == nil {
		locked = append([]config.LockedPack(nil), lock.Packs...)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	ruleRecords := make([]RuleRecord, 0, len(rules))
	for _, rule := range rules {
		ruleRecords = append(ruleRecords, RuleRecord{ID: rule.ID, Digest: sdk.RuleDigest(rule), Pack: rule.Pack, PackVersion: rule.PackVersion})
	}
	bundle := &Bundle{Version: 1, CreatedAt: report.GeneratedAt, Tool: report.Tool, Project: project.Project, Revision: report.Git.Commit, Dirty: report.Git.Dirty, ConfigDigest: report.ConfigDigest, PolicyDigest: report.PolicyDigest, Packs: locked, Rules: ruleRecords, Decision: report, Controls: controlRecords(rules, report.Findings, report.Metrics), Waivers: append([]config.Waiver(nil), report.Waivers...), External: external}
	normalize(bundle)
	return bundle, nil
}

func Verify(project *config.Project, bundle *Bundle, current *engine.Report, rules []sdk.Rule, verifyNow time.Time) error {
	if err := validateBundle(bundle); err != nil {
		return err
	}
	if bundle.Project != project.Project {
		return errors.New("invalid evidence bundle project")
	}
	if bundle.Revision != current.Git.Commit || bundle.Dirty != current.Git.Dirty {
		return errors.New("evidence subject revision or dirty state changed")
	}
	if bundle.ConfigDigest != current.ConfigDigest || bundle.PolicyDigest != current.PolicyDigest {
		return errors.New("evidence config or policy digest changed")
	}
	storedWaivers, _ := json.Marshal(bundle.Waivers)
	currentWaivers, _ := json.Marshal(current.Waivers)
	if !bytes.Equal(storedWaivers, currentWaivers) {
		return errors.New("evidence waiver set changed")
	}
	storedDecision, _ := json.Marshal(decisionContract(bundle.Decision, bundle.Controls))
	currentDecision, _ := json.Marshal(decisionContract(current, controlRecords(rules, current.Findings, current.Metrics)))
	if !bytes.Equal(storedDecision, currentDecision) {
		return errors.New("policy decision no longer reproduces")
	}
	currentPacks := []config.LockedPack{}
	if lock, err := config.LoadLock(filepath.Join(project.Root, config.DefaultLockfile)); err == nil {
		currentPacks = lock.Packs
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	sort.Slice(currentPacks, func(i, j int) bool { return currentPacks[i].Name < currentPacks[j].Name })
	storedPacks, _ := json.Marshal(bundle.Packs)
	actualPacks, _ := json.Marshal(currentPacks)
	if !bytes.Equal(storedPacks, actualPacks) {
		return errors.New("pack lock inputs changed")
	}
	expectedRules := make([]RuleRecord, 0, len(rules))
	for _, rule := range rules {
		expectedRules = append(expectedRules, RuleRecord{ID: rule.ID, Digest: sdk.RuleDigest(rule), Pack: rule.Pack, PackVersion: rule.PackVersion})
	}
	sort.Slice(expectedRules, func(i, j int) bool { return expectedRules[i].ID < expectedRules[j].ID })
	left, _ := json.Marshal(bundle.Rules)
	right, _ := json.Marshal(expectedRules)
	if !bytes.Equal(left, right) {
		return errors.New("evaluated rule set changed")
	}
	policy, err := LoadPolicy(project)
	if err != nil {
		return err
	}
	records := make(map[string]ExternalRecord, len(bundle.External))
	for _, record := range bundle.External {
		if _, exists := records[record.ID]; exists {
			return fmt.Errorf("duplicate external evidence record %s", record.ID)
		}
		records[record.ID] = record
	}
	if len(records) != len(policy.External) {
		return errors.New("external evidence set changed")
	}
	for _, spec := range policy.External {
		currentRecord, err := inspectExternal(project.Root, spec, verifyNow)
		if err != nil {
			return err
		}
		stored, exists := records[spec.ID]
		storedData, _ := json.Marshal(stored)
		currentData, _ := json.Marshal(currentRecord)
		if !exists || !bytes.Equal(storedData, currentData) || !stored.Verified {
			return fmt.Errorf("external evidence %s changed or is unverified", spec.ID)
		}
	}
	return nil
}

func Marshal(bundle *Bundle) ([]byte, error) {
	normalize(bundle)
	data, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}
func Load(path string) (*Bundle, error) {
	data, err := readBoundedRegularFile(path, MaxEvidenceFileSize)
	if err != nil {
		return nil, err
	}
	var bundle Bundle
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&bundle); err != nil {
		return nil, err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, errors.New("exactly one evidence JSON value is required")
		}
		return nil, err
	}
	if err := validateBundle(&bundle); err != nil {
		return nil, err
	}
	return &bundle, nil
}

type decisionContractRecord struct {
	ReportVersion int
	Tool          engine.Tool
	Project       string
	GeneratedAt   time.Time
	ConfigDigest  string
	PolicyDigest  string
	Revision      string
	Dirty         bool
	FailOn        sdk.Severity
	Findings      []sdk.Finding
	Waivers       []config.Waiver
	Changes       []engine.Change
	Baseline      *engine.BaselineStatus
	Comparison    *engine.Comparison
	Summary       engine.Summary
	Controls      []ControlRecord
}

func decisionContract(report *engine.Report, controls []ControlRecord) decisionContractRecord {
	return decisionContractRecord{
		ReportVersion: report.ReportVersion, Tool: report.Tool, Project: report.Project, GeneratedAt: report.GeneratedAt,
		ConfigDigest: report.ConfigDigest, PolicyDigest: report.PolicyDigest, Revision: report.Git.Commit, Dirty: report.Git.Dirty,
		FailOn: report.FailOn, Findings: report.Findings, Waivers: report.Waivers, Changes: report.Changes, Baseline: report.Baseline,
		Comparison: report.Comparison, Summary: report.Summary, Controls: controls,
	}
}

func validateBundle(bundle *Bundle) error {
	if bundle == nil || bundle.Version != 1 || bundle.Decision == nil || bundle.CreatedAt.IsZero() || bundle.Project == "" || !exactGitRevision.MatchString(bundle.Revision) || bundle.Tool.Name != "hoolicy" || bundle.Tool.Version == "" || !exactSHA256.MatchString(bundle.ConfigDigest) || !exactSHA256.MatchString(bundle.PolicyDigest) || bundle.Packs == nil || bundle.Rules == nil || bundle.Controls == nil || bundle.Waivers == nil || bundle.External == nil {
		return errors.New("invalid evidence bundle schema")
	}
	decision := bundle.Decision
	if decision.ReportVersion != 2 || decision.Tool != bundle.Tool || decision.Project != bundle.Project || !decision.GeneratedAt.Equal(bundle.CreatedAt) || decision.ConfigDigest != bundle.ConfigDigest || decision.PolicyDigest != bundle.PolicyDigest || decision.Git.Commit != bundle.Revision || decision.Git.Dirty != bundle.Dirty || !decision.FailOn.Valid() || decision.Findings == nil || decision.Waivers == nil || decision.Metrics.Rules == nil {
		return errors.New("evidence decision envelope does not match bundle")
	}
	if !nonnegativeSummary(decision.Summary) || decision.Metrics.Files < 0 || decision.Metrics.Bytes < 0 || decision.Metrics.DurationMilliseconds < 0 || decision.Metrics.InputCacheHits < 0 || decision.Metrics.ParseCacheHits < 0 {
		return errors.New("invalid evidence decision metrics")
	}
	for _, metric := range decision.Metrics.Rules {
		if metric.RuleID == "" || metric.Inputs < 0 || metric.Findings < 0 || metric.DurationMilliseconds < 0 || metric.InputCacheHits < 0 || metric.ParseCacheHits < 0 {
			return errors.New("invalid evidence rule metrics")
		}
	}
	for _, finding := range decision.Findings {
		if finding.RuleID == "" || finding.Title == "" || finding.Message == "" || finding.Remediation == "" || !finding.Severity.Valid() || !exactFingerprint.MatchString(finding.Fingerprint) || !exactSHA256.MatchString(finding.PolicyDigest) || !exactSHA256.MatchString(finding.FindingDigest) || finding.Location.Line < 0 || finding.Location.Column < 0 || finding.State != sdk.FindingNew && finding.State != sdk.FindingExisting && finding.State != sdk.FindingWaived {
			return errors.New("invalid evidence finding")
		}
	}
	bundleWaivers, _ := json.Marshal(bundle.Waivers)
	decisionWaivers, _ := json.Marshal(decision.Waivers)
	if !bytes.Equal(bundleWaivers, decisionWaivers) {
		return errors.New("evidence decision waiver set does not match bundle")
	}
	for _, waiver := range bundle.Waivers {
		if err := config.ValidateWaiver(waiver, bundle.CreatedAt); err != nil {
			return fmt.Errorf("invalid evidence waiver %s: %w", waiver.ID, err)
		}
	}
	ruleIDs := make(map[string]bool, len(bundle.Rules))
	for _, rule := range bundle.Rules {
		if rule.ID == "" || ruleIDs[rule.ID] || !exactSHA256.MatchString(rule.Digest) {
			return errors.New("invalid or duplicate evidence rule record")
		}
		ruleIDs[rule.ID] = true
	}
	controlKeys := make(map[string]bool, len(bundle.Controls))
	for _, control := range bundle.Controls {
		if !ruleIDs[control.RuleID] || !validControlStatus(control.Status) {
			return errors.New("invalid evidence control record")
		}
		key := control.Framework + "\x00" + control.ID + "\x00" + control.RuleID
		if controlKeys[key] {
			return errors.New("duplicate evidence control record")
		}
		controlKeys[key] = true
	}
	externalIDs := make(map[string]bool, len(bundle.External))
	for _, record := range bundle.External {
		if record.ID == "" || externalIDs[record.ID] || !supportedType(record.Type) || record.Path == "" || !exactSHA256.MatchString(record.Digest) || !exactSHA256.MatchString(record.SubjectDigest) || !record.Verified || record.Metrics == nil {
			return errors.New("invalid or duplicate external evidence record")
		}
		for _, value := range record.Metrics {
			if value < 0 {
				return errors.New("invalid external evidence metrics")
			}
		}
		externalIDs[record.ID] = true
	}
	packNames := make(map[string]bool, len(bundle.Packs))
	for _, pack := range bundle.Packs {
		if pack.Name == "" || packNames[pack.Name] || !exactSHA256.MatchString(pack.Digest) {
			return errors.New("invalid or duplicate evidence pack record")
		}
		packNames[pack.Name] = true
	}
	return nil
}

func nonnegativeSummary(summary engine.Summary) bool {
	return summary.Rules >= 0 && summary.Errors >= 0 && summary.Warnings >= 0 && summary.Info >= 0 && summary.Waived >= 0 && summary.New >= 0 && summary.Existing >= 0 && summary.Fixed >= 0 && summary.Stale >= 0 && summary.Blocking >= 0
}

func validControlStatus(status string) bool {
	switch status {
	case "passed", "failed", "waived", "not-evaluated", "unmapped":
		return true
	}
	return false
}

func normalize(bundle *Bundle) {
	if bundle.Packs == nil {
		bundle.Packs = []config.LockedPack{}
	}
	if bundle.Rules == nil {
		bundle.Rules = []RuleRecord{}
	}
	if bundle.Controls == nil {
		bundle.Controls = []ControlRecord{}
	}
	if bundle.Waivers == nil {
		bundle.Waivers = []config.Waiver{}
	}
	if bundle.External == nil {
		bundle.External = []ExternalRecord{}
	}
	sort.Slice(bundle.Packs, func(i, j int) bool { return bundle.Packs[i].Name < bundle.Packs[j].Name })
	sort.Slice(bundle.Rules, func(i, j int) bool { return bundle.Rules[i].ID < bundle.Rules[j].ID })
	sort.Slice(bundle.Controls, func(i, j int) bool {
		if bundle.Controls[i].Framework != bundle.Controls[j].Framework {
			return bundle.Controls[i].Framework < bundle.Controls[j].Framework
		}
		if bundle.Controls[i].ID != bundle.Controls[j].ID {
			return bundle.Controls[i].ID < bundle.Controls[j].ID
		}
		return bundle.Controls[i].RuleID < bundle.Controls[j].RuleID
	})
	sort.Slice(bundle.External, func(i, j int) bool { return bundle.External[i].ID < bundle.External[j].ID })
}

func controlRecords(rules []sdk.Rule, findings []sdk.Finding, metrics engine.EvaluationMetrics) []ControlRecord {
	byRule := make(map[string][]sdk.Finding)
	for _, finding := range findings {
		byRule[finding.RuleID] = append(byRule[finding.RuleID], finding)
	}
	records := []ControlRecord{}
	evaluated := map[string]bool{}
	for _, metric := range metrics.Rules {
		evaluated[metric.RuleID] = true
	}
	for _, rule := range rules {
		status := "passed"
		if len(metrics.Rules) > 0 && !evaluated[rule.ID] {
			status = "not-evaluated"
		}
		if len(byRule[rule.ID]) > 0 {
			status = "waived"
			for _, finding := range byRule[rule.ID] {
				if !finding.Waived {
					status = "failed"
					break
				}
			}
		}
		if len(rule.Controls) == 0 {
			records = append(records, ControlRecord{RuleID: rule.ID, Status: "unmapped"})
			continue
		}
		for _, control := range rule.Controls {
			records = append(records, ControlRecord{Framework: control.Framework, ID: control.ID, RuleID: rule.ID, Status: status})
		}
	}
	sort.Slice(records, func(i, j int) bool {
		if records[i].Framework != records[j].Framework {
			return records[i].Framework < records[j].Framework
		}
		if records[i].ID != records[j].ID {
			return records[i].ID < records[j].ID
		}
		return records[i].RuleID < records[j].RuleID
	})
	return records
}

func InspectExternal(root string, spec ExternalSpec, now time.Time) (ExternalRecord, error) {
	_, absolute, err := safepath.Existing(root, spec.Path)
	if err != nil {
		return ExternalRecord{}, err
	}
	data, err := readBoundedRegularFile(absolute, MaxEvidenceFileSize)
	if err != nil {
		return ExternalRecord{}, err
	}
	return InspectExternalBytes(spec, data, now)
}

func readBoundedRegularFile(path string, maximum int64) ([]byte, error) {
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if pathInfo.Mode()&os.ModeSymlink != 0 || !pathInfo.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: expected a regular file", path)
	}
	if pathInfo.Size() > maximum {
		return nil, fmt.Errorf("%s: evidence exceeds %d bytes", path, maximum)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(opened, pathInfo) || opened.Size() > maximum {
		return nil, fmt.Errorf("%s: evidence changed, is not regular, or exceeds %d bytes", path, maximum)
	}
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maximum || int64(len(data)) != opened.Size() {
		return nil, fmt.Errorf("%s: evidence changed or exceeds %d bytes", path, maximum)
	}
	return data, nil
}

func InspectExternalBytes(spec ExternalSpec, data []byte, now time.Time) (ExternalRecord, error) {
	if !supportedType(spec.Type) {
		return ExternalRecord{}, fmt.Errorf("unsupported evidence type %s", spec.Type)
	}
	if !exactSHA256.MatchString(spec.SHA256) || !exactSHA256.MatchString(spec.SubjectDigest) {
		return ExternalRecord{}, errors.New("evidence and subject digests must be exact SHA-256 values")
	}
	digest := sha(data)
	if digest != spec.SHA256 {
		return ExternalRecord{}, fmt.Errorf("digest mismatch: expected %s, got %s", spec.SHA256, digest)
	}
	record := ExternalRecord{ID: spec.ID, Type: spec.Type, Path: filepath.ToSlash(spec.Path), Digest: digest, SubjectDigest: spec.SubjectDigest, Metrics: map[string]int{}, Verified: true}
	if spec.Type == "junit" {
		generated, metrics, properties, err := inspectJUnit(data)
		if err != nil {
			return ExternalRecord{}, err
		}
		if !propertyMatches(properties, "hoolicy.subjectDigest", spec.SubjectDigest) {
			return ExternalRecord{}, errors.New("declared subject digest is absent from JUnit hoolicy.subjectDigest property")
		}
		record.GeneratedAt = generated
		record.Metrics = metrics
		if spec.RequiredProducer != "" && !propertyMatches(properties, "hoolicy.producer", spec.RequiredProducer) {
			return ExternalRecord{}, errors.New("required producer is absent from JUnit hoolicy.producer property")
		}
	} else {
		var value any
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.UseNumber()
		if err := decoder.Decode(&value); err != nil {
			return ExternalRecord{}, err
		}
		var extra any
		if err := decoder.Decode(&extra); err != io.EOF {
			if err == nil {
				return ExternalRecord{}, errors.New("exactly one external evidence JSON value is required")
			}
			return ExternalRecord{}, err
		}
		if err := validateJSONType(spec.Type, value); err != nil {
			return ExternalRecord{}, err
		}
		object := value.(map[string]any)
		if !jsonSubjectBound(spec.Type, object, spec.SubjectDigest) {
			return ExternalRecord{}, errors.New("declared subject digest is absent from the adapter-defined subject field")
		}
		if spec.RequiredProducer != "" && !jsonProducerMatches(spec.Type, object, spec.RequiredProducer) {
			return ExternalRecord{}, errors.New("required producer is absent from the adapter-defined producer field")
		}
		record.GeneratedAt = jsonTimestamp(spec.Type, object)
		record.Metrics = jsonMetrics(spec.Type, value)
	}
	if spec.MaximumAge != "" {
		if record.GeneratedAt.IsZero() {
			return ExternalRecord{}, errors.New("freshness timestamp is absent")
		}
		maximum, _ := time.ParseDuration(spec.MaximumAge)
		if now.Sub(record.GeneratedAt) > maximum || record.GeneratedAt.After(now.Add(5*time.Minute)) {
			return ExternalRecord{}, errors.New("evidence is stale or from the future")
		}
	}
	items := record.Metrics["items"]
	if spec.MinimumItems > 0 && items < spec.MinimumItems {
		return ExternalRecord{}, fmt.Errorf("items %d below minimum %d", items, spec.MinimumItems)
	}
	if failures := record.Metrics["failures"]; failures > spec.MaximumFailures {
		return ExternalRecord{}, fmt.Errorf("failures %d exceed maximum %d", failures, spec.MaximumFailures)
	}
	return record, nil
}

func inspectExternal(root string, spec ExternalSpec, now time.Time) (ExternalRecord, error) {
	return InspectExternal(root, spec, now)
}

func supportedType(value string) bool {
	switch value {
	case "sarif", "cyclonedx", "spdx", "junit", "provenance":
		return true
	}
	return false
}
func sha(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}
func validateJSONType(kind string, value any) error {
	object, ok := value.(map[string]any)
	if !ok {
		return errors.New("evidence root must be an object")
	}
	switch kind {
	case "sarif":
		runs, ok := object["runs"].([]any)
		if object["version"] != "2.1.0" || !ok || len(runs) == 0 {
			return errors.New("SARIF 2.1.0 requires at least one run")
		}
		for _, raw := range runs {
			run, ok := raw.(map[string]any)
			tool, toolOK := objectAt(run, "tool")
			driver, driverOK := objectAt(tool, "driver")
			if !ok || !toolOK || !driverOK || stringAt(driver, "name") == "" {
				return errors.New("each SARIF run requires tool.driver.name")
			}
			if results, exists := run["results"]; exists {
				if _, ok := results.([]any); !ok {
					return errors.New("SARIF run results must be an array")
				}
			}
		}
	case "cyclonedx":
		metadata, metadataOK := objectAt(object, "metadata")
		_, componentsOK := object["components"].([]any)
		if object["bomFormat"] != "CycloneDX" || !strings.HasPrefix(stringAt(object, "specVersion"), "1.") || !metadataOK || !componentsOK {
			return errors.New("CycloneDX requires bomFormat, 1.x specVersion, metadata, and components")
		}
		if timestamp := stringAt(metadata, "timestamp"); timestamp != "" {
			if _, err := time.Parse(time.RFC3339, timestamp); err != nil {
				return errors.New("CycloneDX metadata.timestamp must be RFC3339")
			}
		}
	case "spdx":
		creation, creationOK := objectAt(object, "creationInfo")
		creators, creatorsOK := creation["creators"].([]any)
		_, packagesOK := object["packages"].([]any)
		_, filesOK := object["files"].([]any)
		version := stringAt(object, "spdxVersion")
		if (version != "SPDX-2.2" && version != "SPDX-2.3") || stringAt(object, "SPDXID") == "" || stringAt(object, "dataLicense") == "" || stringAt(object, "documentNamespace") == "" || !creationOK || !creatorsOK || len(creators) == 0 || !packagesOK && !filesOK || len(spdxDescribedIDs(object)) == 0 {
			return errors.New("SPDX 2.2/2.3 requires document identity, creationInfo, a document description relationship, and package or file entries")
		}
		if _, err := time.Parse(time.RFC3339, stringAt(creation, "created")); err != nil {
			return errors.New("SPDX creationInfo.created must be RFC3339")
		}
	case "provenance":
		subjects, subjectsOK := object["subject"].([]any)
		_, predicateOK := objectAt(object, "predicate")
		if object["_type"] != "https://in-toto.io/Statement/v1" || !subjectsOK || len(subjects) == 0 || stringAt(object, "predicateType") == "" || !predicateOK {
			return errors.New("in-toto Statement v1 requires subjects, predicateType, and predicate")
		}
		for _, raw := range subjects {
			subject, ok := raw.(map[string]any)
			digests, digestOK := objectAt(subject, "digest")
			if !ok || !digestOK || len(digests) == 0 {
				return errors.New("each in-toto subject requires a digest")
			}
		}
	}
	return nil
}

func jsonSubjectBound(kind string, object map[string]any, digest string) bool {
	hexDigest := strings.TrimPrefix(digest, "sha256:")
	switch kind {
	case "sarif":
		for _, run := range objectsAt(object, "runs") {
			properties, _ := objectAt(run, "properties")
			if stringAt(properties, "hoolicy.subjectDigest") == digest {
				return true
			}
		}
	case "cyclonedx":
		metadata, _ := objectAt(object, "metadata")
		component, _ := objectAt(metadata, "component")
		return checksumMatches(objectsAt(component, "hashes"), "alg", "content", hexDigest)
	case "spdx":
		described := spdxDescribedIDs(object)
		for _, item := range append(objectsAt(object, "packages"), objectsAt(object, "files")...) {
			if described[stringAt(item, "SPDXID")] && checksumMatches(objectsAt(item, "checksums"), "algorithm", "checksumValue", hexDigest) {
				return true
			}
		}
	case "provenance":
		for _, subject := range objectsAt(object, "subject") {
			digests, _ := objectAt(subject, "digest")
			if stringAt(digests, "sha256") == hexDigest {
				return true
			}
		}
	}
	return false
}

func spdxDescribedIDs(object map[string]any) map[string]bool {
	described := map[string]bool{}
	if values, ok := object["documentDescribes"].([]any); ok {
		for _, value := range values {
			if id, ok := value.(string); ok && id != "" {
				described[id] = true
			}
		}
	}
	documentID := stringAt(object, "SPDXID")
	for _, relation := range objectsAt(object, "relationships") {
		if stringAt(relation, "spdxElementId") == documentID && stringAt(relation, "relationshipType") == "DESCRIBES" {
			if id := stringAt(relation, "relatedSpdxElement"); id != "" {
				described[id] = true
			}
		}
	}
	return described
}

func jsonProducerMatches(kind string, object map[string]any, producer string) bool {
	switch kind {
	case "sarif":
		for _, run := range objectsAt(object, "runs") {
			tool, _ := objectAt(run, "tool")
			driver, _ := objectAt(tool, "driver")
			if stringAt(driver, "name") == producer || stringAt(driver, "fullName") == producer {
				return true
			}
		}
	case "cyclonedx":
		metadata, _ := objectAt(object, "metadata")
		if tools, ok := metadata["tools"].([]any); ok {
			for _, raw := range tools {
				if tool, ok := raw.(map[string]any); ok && stringAt(tool, "name") == producer {
					return true
				}
			}
		}
		tools, _ := objectAt(metadata, "tools")
		for _, tool := range append(objectsAt(tools, "components"), objectsAt(tools, "services")...) {
			if stringAt(tool, "name") == producer {
				return true
			}
		}
	case "spdx":
		creation, _ := objectAt(object, "creationInfo")
		if creators, ok := creation["creators"].([]any); ok {
			for _, raw := range creators {
				creator, _ := raw.(string)
				if creator == "Tool: "+producer || strings.HasPrefix(creator, "Tool: "+producer+"-") {
					return true
				}
			}
		}
	case "provenance":
		predicate, _ := objectAt(object, "predicate")
		builder, _ := objectAt(predicate, "builder")
		if stringAt(builder, "id") == producer {
			return true
		}
		runDetails, _ := objectAt(predicate, "runDetails")
		builder, _ = objectAt(runDetails, "builder")
		return stringAt(builder, "id") == producer
	}
	return false
}

func jsonTimestamp(kind string, object map[string]any) time.Time {
	var value string
	switch kind {
	case "sarif":
		for _, run := range objectsAt(object, "runs") {
			for _, invocation := range objectsAt(run, "invocations") {
				if value = stringAt(invocation, "endTimeUtc"); value != "" {
					break
				}
			}
			if value == "" {
				properties, _ := objectAt(run, "properties")
				value = stringAt(properties, "hoolicy.generatedAt")
			}
			if value != "" {
				break
			}
		}
	case "cyclonedx":
		metadata, _ := objectAt(object, "metadata")
		value = stringAt(metadata, "timestamp")
	case "spdx":
		creation, _ := objectAt(object, "creationInfo")
		value = stringAt(creation, "created")
	case "provenance":
		predicate, _ := objectAt(object, "predicate")
		metadata, _ := objectAt(predicate, "metadata")
		value = stringAt(metadata, "buildFinishedOn")
		if value == "" {
			runDetails, _ := objectAt(predicate, "runDetails")
			metadata, _ = objectAt(runDetails, "metadata")
			value = stringAt(metadata, "finishedOn")
		}
	}
	parsed, _ := time.Parse(time.RFC3339, value)
	return parsed
}

func objectAt(object map[string]any, key string) (map[string]any, bool) {
	value, ok := object[key].(map[string]any)
	return value, ok
}

func objectsAt(object map[string]any, key string) []map[string]any {
	values, _ := object[key].([]any)
	result := make([]map[string]any, 0, len(values))
	for _, raw := range values {
		if value, ok := raw.(map[string]any); ok {
			result = append(result, value)
		}
	}
	return result
}

func stringAt(object map[string]any, key string) string {
	value, _ := object[key].(string)
	return value
}

func checksumMatches(checksums []map[string]any, algorithmKey, valueKey, expected string) bool {
	for _, checksum := range checksums {
		algorithm := strings.ToUpper(strings.ReplaceAll(stringAt(checksum, algorithmKey), "-", ""))
		if algorithm == "SHA256" && strings.EqualFold(stringAt(checksum, valueKey), expected) {
			return true
		}
	}
	return false
}
func jsonMetrics(kind string, value any) map[string]int {
	metrics := map[string]int{"items": 0, "failures": 0}
	object, _ := value.(map[string]any)
	var list any
	switch kind {
	case "sarif":
		if runs, ok := object["runs"].([]any); ok {
			for _, run := range runs {
				if item, ok := run.(map[string]any); ok {
					if results, ok := item["results"].([]any); ok {
						metrics["items"] += len(results)
						metrics["failures"] += len(results)
					}
				}
			}
		}
	case "cyclonedx":
		list = object["components"]
	case "spdx":
		metrics["items"] = len(objectsAt(object, "packages")) + len(objectsAt(object, "files"))
	case "provenance":
		list = object["subject"]
	}
	if values, ok := list.([]any); ok {
		metrics["items"] = len(values)
	}
	return metrics
}

type junitSuites struct {
	XMLName    xml.Name        `xml:"testsuites"`
	Tests      int             `xml:"tests,attr"`
	Failures   int             `xml:"failures,attr"`
	Timestamp  string          `xml:"timestamp,attr"`
	Properties []junitProperty `xml:"properties>property"`
	Suites     []struct {
		Tests      int             `xml:"tests,attr"`
		Failures   int             `xml:"failures,attr"`
		Timestamp  string          `xml:"timestamp,attr"`
		Properties []junitProperty `xml:"properties>property"`
	} `xml:"testsuite"`
}

type junitProperty struct {
	Name  string `xml:"name,attr"`
	Value string `xml:"value,attr"`
}

func inspectJUnit(data []byte) (time.Time, map[string]int, []junitProperty, error) {
	if bytes.Contains(bytes.ToUpper(data), []byte("<!DOCTYPE")) {
		return time.Time{}, nil, nil, errors.New("JUnit document type declarations are forbidden")
	}
	var suites junitSuites
	if err := xml.Unmarshal(data, &suites); err != nil {
		return time.Time{}, nil, nil, err
	}
	if suites.XMLName.Local != "testsuites" {
		return time.Time{}, nil, nil, errors.New("JUnit root must be testsuites")
	}
	properties := append([]junitProperty(nil), suites.Properties...)
	tests, failures := suites.Tests, suites.Failures
	timestamp := suites.Timestamp
	for _, suite := range suites.Suites {
		if suite.Tests < 0 || suite.Failures < 0 {
			return time.Time{}, nil, nil, errors.New("JUnit counts must not be negative")
		}
		if suites.Tests == 0 {
			tests += suite.Tests
			failures += suite.Failures
		}
		properties = append(properties, suite.Properties...)
		if timestamp == "" {
			timestamp = suite.Timestamp
		}
	}
	if tests < 0 || failures < 0 || failures > tests {
		return time.Time{}, nil, nil, errors.New("JUnit test and failure counts are invalid")
	}
	var generated time.Time
	if timestamp != "" {
		var err error
		generated, err = time.Parse(time.RFC3339, timestamp)
		if err != nil {
			return time.Time{}, nil, nil, errors.New("JUnit timestamp must be RFC3339")
		}
	}
	return generated, map[string]int{"items": tests, "failures": failures}, properties, nil
}

func propertyMatches(properties []junitProperty, name, value string) bool {
	for _, property := range properties {
		if property.Name == name && property.Value == value {
			return true
		}
	}
	return false
}
