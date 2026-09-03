package report

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"html"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/openhoo/hoolicy/internal/config"
	"github.com/openhoo/hoolicy/internal/engine"
	"github.com/openhoo/hoolicy/internal/repository"
	"github.com/openhoo/hoolicy/internal/safepath"
	"github.com/openhoo/hoolicy/sdk"
)

const MaxReportFileSize int64 = 64 << 20

func Write(writer io.Writer, format string, report *engine.Report, color bool) error {
	switch strings.ToLower(format) {
	case "", "text":
		return writeText(writer, report, color)
	case "json":
		return writeJSON(writer, report)
	case "sarif":
		return writeSARIF(writer, report)
	case "junit":
		return writeJUnit(writer, report)
	case "github":
		return writeGitHubSummary(writer, report)
	case "gitlab-codequality":
		return writeGitLabCodeQuality(writer, report)
	default:
		return fmt.Errorf("unknown report format %q", format)
	}
}

func ValidFormat(format string) bool {
	switch strings.ToLower(format) {
	case "", "text", "json", "sarif", "junit", "github", "gitlab-codequality":
		return true
	default:
		return false
	}
}

func writeJSON(writer io.Writer, report *engine.Report) error {
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	return encoder.Encode(report)
}

func writeText(writer io.Writer, report *engine.Report, color bool) error {
	for _, item := range report.Findings {
		label := strings.ToUpper(string(item.Severity))
		if item.Waived {
			label = "WAIVED"
		} else if item.State == sdk.FindingExisting {
			label = "EXISTING"
		}
		if color {
			label = colorLabel(label, item)
		}
		location := singleLine(item.Location.Path)
		if location != "" && item.Location.Line > 0 {
			location += fmt.Sprintf(":%d:%d", item.Location.Line, item.Location.Column)
		}
		if location != "" {
			location += " "
		}
		fmt.Fprintf(writer, "%s %s%s %s\n", label, location, item.RuleID, singleLine(item.Message))
		fmt.Fprintf(writer, "  Fix: %s\n", singleLine(item.Remediation))
		if item.Waived {
			fmt.Fprintf(writer, "  Waiver: %s\n", item.WaiverID)
		}
	}
	for _, change := range report.Changes {
		fmt.Fprintf(writer, "%s %s %s (%s)\n", strings.ToUpper(change.State), change.RuleID, shortFingerprint(change.Fingerprint), singleLine(change.Reason))
	}
	fmt.Fprintf(writer, "\n%d rules, %d findings: %d new, %d existing, %d waived, %d fixed, %d stale, %d blocking\n", report.Summary.Rules, len(report.Findings), report.Summary.New, report.Summary.Existing, report.Summary.Waived, report.Summary.Fixed, report.Summary.Stale, report.Summary.Blocking)
	return nil
}

func shortFingerprint(value string) string {
	if len(value) > 12 {
		return value[:12]
	}
	return value
}

func singleLine(value string) string {
	return strings.TrimSpace(strings.Map(func(character rune) rune {
		if character == '\n' || character == '\r' || character == '\t' {
			return ' '
		}
		if unicode.IsControl(character) {
			return -1
		}
		return character
	}, value))
}

func colorLabel(label string, item sdk.Finding) string {
	code := "36"
	if item.Waived {
		code = "2"
	} else if item.Severity == sdk.SeverityError {
		code = "31"
	} else if item.Severity == sdk.SeverityWarning {
		code = "33"
	}
	return "\x1b[" + code + "m" + label + "\x1b[0m"
}

type sarifLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}
type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}
type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}
type sarifDriver struct {
	Name    string      `json:"name"`
	Version string      `json:"version"`
	Rules   []sarifRule `json:"rules"`
}
type sarifRule struct {
	ID               string       `json:"id"`
	Name             string       `json:"name"`
	ShortDescription sarifMessage `json:"shortDescription"`
	Help             sarifMessage `json:"help"`
}
type sarifResult struct {
	RuleID              string             `json:"ruleId"`
	Level               string             `json:"level"`
	Message             sarifMessage       `json:"message"`
	Locations           []sarifLocation    `json:"locations,omitempty"`
	PartialFingerprints map[string]string  `json:"partialFingerprints"`
	Suppressions        []sarifSuppression `json:"suppressions,omitempty"`
}
type sarifMessage struct {
	Text string `json:"text"`
}
type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}
type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           sarifRegion   `json:"region,omitempty"`
}
type sarifArtifact struct {
	URI string `json:"uri"`
}
type sarifRegion struct {
	StartLine   int `json:"startLine,omitempty"`
	StartColumn int `json:"startColumn,omitempty"`
}
type sarifSuppression struct {
	Kind          string `json:"kind"`
	Justification string `json:"justification"`
}

func writeSARIF(writer io.Writer, input *engine.Report) error {
	rules := map[string]sarifRule{}
	results := make([]sarifResult, 0, len(input.Findings))
	for _, item := range input.Findings {
		rules[item.RuleID] = sarifRule{ID: item.RuleID, Name: item.Title, ShortDescription: sarifMessage{Text: item.Title}, Help: sarifMessage{Text: item.Remediation}}
		level := "note"
		if item.Severity == sdk.SeverityError {
			level = "error"
		} else if item.Severity == sdk.SeverityWarning {
			level = "warning"
		}
		result := sarifResult{RuleID: item.RuleID, Level: level, Message: sarifMessage{Text: item.Message}, PartialFingerprints: map[string]string{"hoolicy/v1": item.Fingerprint}}
		if item.Location.Path != "" {
			result.Locations = []sarifLocation{{PhysicalLocation: sarifPhysical{ArtifactLocation: sarifArtifact{URI: filepath.ToSlash(item.Location.Path)}, Region: sarifRegion{StartLine: item.Location.Line, StartColumn: item.Location.Column}}}}
		}
		if item.Waived {
			result.Suppressions = []sarifSuppression{{Kind: "external", Justification: "Hoolicy waiver " + item.WaiverID}}
		}
		results = append(results, result)
	}
	ruleList := make([]sarifRule, 0, len(rules))
	for _, rule := range rules {
		ruleList = append(ruleList, rule)
	}
	sort.Slice(ruleList, func(i, j int) bool { return ruleList[i].ID < ruleList[j].ID })
	log := sarifLog{Version: "2.1.0", Schema: "https://json.schemastore.org/sarif-2.1.0.json", Runs: []sarifRun{{Tool: sarifTool{Driver: sarifDriver{Name: "hoolicy", Version: input.Tool.Version, Rules: ruleList}}, Results: results}}}
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	return encoder.Encode(log)
}

type testSuites struct {
	XMLName  xml.Name    `xml:"testsuites"`
	Name     string      `xml:"name,attr"`
	Tests    int         `xml:"tests,attr"`
	Failures int         `xml:"failures,attr"`
	Skipped  int         `xml:"skipped,attr"`
	Suites   []testSuite `xml:"testsuite"`
}
type testSuite struct {
	Name     string     `xml:"name,attr"`
	Tests    int        `xml:"tests,attr"`
	Failures int        `xml:"failures,attr"`
	Skipped  int        `xml:"skipped,attr"`
	Cases    []testCase `xml:"testcase"`
}
type testCase struct {
	Name      string       `xml:"name,attr"`
	Classname string       `xml:"classname,attr"`
	Failure   *testFailure `xml:"failure,omitempty"`
	Skipped   *testSkipped `xml:"skipped,omitempty"`
	SystemOut string       `xml:"system-out,omitempty"`
}
type testFailure struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr"`
	Body    string `xml:",chardata"`
}
type testSkipped struct {
	Message string `xml:"message,attr"`
}

func writeJUnit(writer io.Writer, input *engine.Report) error {
	suite := testSuite{Name: input.Project, Tests: len(input.Findings)}
	for _, item := range input.Findings {
		fingerprint := item.Fingerprint
		if len(fingerprint) > 12 {
			fingerprint = fingerprint[:12]
		}
		caseItem := testCase{Name: strings.TrimSpace(item.RuleID + " " + fingerprint), Classname: "hoolicy." + input.Project, SystemOut: item.Location.Path}
		if item.Waived || item.State == sdk.FindingExisting {
			reason := "Existing finding"
			if item.Waived {
				reason = "Waived by " + item.WaiverID
			}
			caseItem.Skipped = &testSkipped{Message: reason}
			suite.Skipped++
		} else if item.Severity.Rank() >= input.FailOn.Rank() {
			caseItem.Failure = &testFailure{Message: item.Message, Type: string(item.Severity), Body: item.Remediation}
			suite.Failures++
		} else {
			caseItem.SystemOut = strings.TrimSpace(caseItem.SystemOut + "\nNon-blocking: " + item.Message)
		}
		suite.Cases = append(suite.Cases, caseItem)
	}
	suites := testSuites{Name: "hoolicy", Tests: suite.Tests, Failures: suite.Failures, Skipped: suite.Skipped, Suites: []testSuite{suite}}
	var buffer bytes.Buffer
	buffer.WriteString(xml.Header)
	encoder := xml.NewEncoder(&buffer)
	encoder.Indent("", "  ")
	if err := encoder.Encode(suites); err != nil {
		return err
	}
	buffer.WriteByte('\n')
	_, err := writer.Write(buffer.Bytes())
	return err
}

func writeGitHubSummary(writer io.Writer, input *engine.Report) error {
	fmt.Fprintln(writer, "## Hoolicy policy summary")
	fmt.Fprintf(writer, "\n**%d blocking**, %d new, %d existing, %d waived, %d fixed, %d stale across %d rules.\n", input.Summary.Blocking, input.Summary.New, input.Summary.Existing, input.Summary.Waived, input.Summary.Fixed, input.Summary.Stale, input.Summary.Rules)
	if input.Baseline != nil && input.Baseline.PolicyChanged {
		fmt.Fprintln(writer, "\nBaseline policy digest differs from current policy; review stale and new findings.")
	}
	if len(input.Findings) == 0 && len(input.Changes) == 0 {
		fmt.Fprintln(writer, "\nNo findings.")
		return nil
	}
	fmt.Fprintln(writer, "\n| State | Severity | Rule | Location | Finding |")
	fmt.Fprintln(writer, "| --- | --- | --- | --- | --- |")
	const limit = 100
	count := 0
	for _, item := range input.Findings {
		if count == limit {
			break
		}
		state := string(item.State)
		if state == "" {
			state = string(sdk.FindingNew)
		}
		location := item.Location.Path
		if item.Location.Line > 0 {
			location += fmt.Sprintf(":%d", item.Location.Line)
		}
		fmt.Fprintf(writer, "| %s | %s | `%s` | `%s` | %s<br><sub>Fix: %s</sub> |\n", markdownCell(state), markdownCell(string(item.Severity)), markdownCell(item.RuleID), markdownCell(location), markdownCell(item.Message), markdownCell(item.Remediation))
		count++
	}
	for _, change := range input.Changes {
		if count == limit {
			break
		}
		fmt.Fprintf(writer, "| %s | %s | `%s` |  | %s |\n", markdownCell(change.State), markdownCell(string(change.Severity)), markdownCell(change.RuleID), markdownCell(change.Reason))
		count++
	}
	if len(input.Findings)+len(input.Changes) > limit {
		fmt.Fprintf(writer, "\nShowing first %d items. Use JSON report for complete evidence.\n", limit)
	}
	return nil
}

func markdownCell(value string) string {
	value = singleLine(value)
	value = html.EscapeString(value)
	value = strings.ReplaceAll(value, "|", "\\|")
	value = strings.ReplaceAll(value, "`", "\\`")
	return value
}

type gitLabFinding struct {
	Description string         `json:"description"`
	CheckName   string         `json:"check_name"`
	Fingerprint string         `json:"fingerprint"`
	Severity    string         `json:"severity"`
	Location    gitLabLocation `json:"location"`
}
type gitLabLocation struct {
	Path  string      `json:"path"`
	Lines gitLabLines `json:"lines"`
}
type gitLabLines struct {
	Begin int `json:"begin"`
}

func writeGitLabCodeQuality(writer io.Writer, input *engine.Report) error {
	findings := make([]gitLabFinding, 0, len(input.Findings))
	for _, item := range input.Findings {
		path := strings.TrimPrefix(filepath.ToSlash(item.Location.Path), "./")
		if path == "" {
			path = "hoolicy.yaml"
		}
		line := item.Location.Line
		if line < 1 {
			line = 1
		}
		severity := "info"
		if item.Severity == sdk.SeverityWarning {
			severity = "minor"
		}
		if item.Severity == sdk.SeverityError {
			severity = "major"
		}
		state := string(item.State)
		if state == "" {
			state = string(sdk.FindingNew)
		}
		description := "State: " + state + ". " + item.Message + " Remediation: " + item.Remediation
		if item.Waived {
			description += " Waiver: " + item.WaiverID
		}
		findings = append(findings, gitLabFinding{
			Description: description,
			CheckName:   item.RuleID, Fingerprint: item.Fingerprint, Severity: severity,
			Location: gitLabLocation{Path: path, Lines: gitLabLines{Begin: line}},
		})
	}
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	return encoder.Encode(findings)
}

type Diff struct {
	BeforePolicyDigest string          `json:"beforePolicyDigest"`
	AfterPolicyDigest  string          `json:"afterPolicyDigest"`
	Added              []sdk.Finding   `json:"added"`
	Removed            []sdk.Finding   `json:"removed"`
	Changed            []FindingChange `json:"changed"`
	Waivers            WaiverDiff      `json:"waivers"`
}

type FindingChange struct {
	Fingerprint string      `json:"fingerprint"`
	Before      sdk.Finding `json:"before"`
	After       sdk.Finding `json:"after"`
}

type WaiverDiff struct {
	Added      []config.Waiver     `json:"added"`
	Removed    []config.Waiver     `json:"removed"`
	Renewed    []WaiverRenewal     `json:"renewed"`
	ScopeGrown []WaiverScopeGrowth `json:"scopeGrown"`
	Expired    []config.Waiver     `json:"expired"`
}

type WaiverRenewal struct {
	ID            string      `json:"id"`
	BeforeExpires config.Date `json:"beforeExpires"`
	AfterExpires  config.Date `json:"afterExpires"`
}

type WaiverScopeGrowth struct {
	ID                string   `json:"id"`
	AddedFingerprints []string `json:"addedFingerprints"`
	AddedPaths        []string `json:"addedPaths"`
}

type legacySummary struct {
	Rules    int `json:"rules"`
	Errors   int `json:"errors"`
	Warnings int `json:"warnings"`
	Info     int `json:"info"`
	Waived   int `json:"waived"`
	Blocking int `json:"blocking"`
}

type legacyReport struct {
	ReportVersion int             `json:"reportVersion"`
	Tool          engine.Tool     `json:"tool"`
	Project       string          `json:"project"`
	GeneratedAt   time.Time       `json:"generatedAt"`
	ConfigDigest  string          `json:"configDigest"`
	Git           sdk.GitContext  `json:"git"`
	FailOn        sdk.Severity    `json:"failOn"`
	Findings      []legacyFinding `json:"findings"`
	Summary       legacySummary   `json:"summary"`
}

type legacyFinding struct {
	RuleID      string         `json:"ruleId"`
	Title       string         `json:"title"`
	Message     string         `json:"message"`
	Remediation string         `json:"remediation"`
	Severity    sdk.Severity   `json:"severity"`
	Location    sdk.Location   `json:"location"`
	Key         string         `json:"key,omitempty"`
	Fingerprint string         `json:"fingerprint"`
	Controls    []sdk.Control  `json:"controls,omitempty"`
	Pack        string         `json:"pack,omitempty"`
	Waived      bool           `json:"waived,omitempty"`
	WaiverID    string         `json:"waiverId,omitempty"`
	Fix         *sdk.Fix       `json:"fix,omitempty"`
	Properties  map[string]any `json:"properties,omitempty"`
}

var (
	legacyRuleIDPattern = regexp.MustCompile(`^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$`)
	legacyDigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	fingerprintPattern  = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// LegacyProjectDigest computes the v1 configDigest exactly as released.
// Unlike the v2 policy digest, it deliberately excludes evidence input.
func LegacyProjectDigest(project *config.Project, rules []sdk.Rule) (string, error) {
	if project == nil {
		return "", errors.New("historical project configuration is required")
	}
	hash := sha256.New()
	writeInput := func(label, path string) error {
		data, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		_, _ = hash.Write([]byte(label))
		_, _ = hash.Write([]byte{0})
		_, _ = hash.Write(data)
		_, _ = hash.Write([]byte{0})
		return nil
	}
	if err := writeInput(config.DefaultFilename, project.Path); err != nil {
		return "", err
	}
	if err := writeInput(config.DefaultLockfile, filepath.Join(project.Root, config.DefaultLockfile)); err != nil {
		return "", err
	}
	waiverLabel := filepath.ToSlash(project.Waivers)
	waiverPath := filepath.Join(project.Root, filepath.FromSlash(project.Waivers))
	if err := writeInput(waiverLabel, waiverPath); err != nil {
		return "", err
	}
	active, err := json.Marshal(rules)
	if err != nil {
		return "", fmt.Errorf("encode active policy digest: %w", err)
	}
	_, _ = hash.Write(active)
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

func decodeLegacy(data []byte, path string) (*legacyReport, error) {
	var input legacyReport
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("%s: exactly one JSON value is required", path)
		}
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(data, &envelope); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	for _, field := range []string{"reportVersion", "tool", "project", "generatedAt", "configDigest", "git", "failOn", "findings", "summary"} {
		if _, exists := envelope[field]; !exists {
			return nil, fmt.Errorf("%s: missing required v1 field %s", path, field)
		}
	}
	if input.ReportVersion != 1 {
		return nil, fmt.Errorf("%s: unsupported report version %d", path, input.ReportVersion)
	}
	if input.Findings == nil {
		input.Findings = []legacyFinding{}
	}
	if input.Git.CommitSubjects == nil {
		input.Git.CommitSubjects = []sdk.Commit{}
	}
	return &input, nil
}

func legacyEngineReport(input *legacyReport) *engine.Report {
	result := &engine.Report{
		ReportVersion: input.ReportVersion,
		Tool:          input.Tool,
		Project:       input.Project,
		GeneratedAt:   input.GeneratedAt,
		ConfigDigest:  input.ConfigDigest,
		Git:           input.Git,
		FailOn:        input.FailOn,
		Summary: engine.Summary{
			Rules: input.Summary.Rules, Errors: input.Summary.Errors,
			Warnings: input.Summary.Warnings, Info: input.Summary.Info,
			Waived: input.Summary.Waived, Blocking: input.Summary.Blocking,
		},
	}
	result.Findings = make([]sdk.Finding, 0, len(input.Findings))
	for _, finding := range input.Findings {
		result.Findings = append(result.Findings, sdk.Finding{
			RuleID: finding.RuleID, Title: finding.Title, Message: finding.Message,
			Remediation: finding.Remediation, Severity: finding.Severity, Location: finding.Location,
			Key: finding.Key, Fingerprint: finding.Fingerprint,
			Controls: append([]sdk.Control(nil), finding.Controls...), Pack: finding.Pack,
			Waived: finding.Waived, WaiverID: finding.WaiverID, Fix: finding.Fix,
			Properties: finding.Properties,
		})
	}
	return result
}

func legacyFindingFingerprint(finding sdk.Finding) string {
	hash := sha256.Sum256([]byte(strings.Join([]string{
		finding.RuleID,
		filepath.ToSlash(filepath.Clean(finding.Location.Path)),
		fmt.Sprintf("%d:%d", finding.Location.Line, finding.Location.Column),
		finding.Key,
	}, "\x00")))
	return hex.EncodeToString(hash[:])
}

func validateLegacyEnvelope(input *legacyReport, project *config.Project) error {
	if input == nil || project == nil {
		return errors.New("historical project configuration is required")
	}
	if input.Tool.Name != "hoolicy" || strings.TrimSpace(input.Tool.Version) == "" {
		return errors.New("report v1 tool must identify hoolicy with a version")
	}
	if input.Project == "" || input.Project != project.Project {
		return fmt.Errorf("report project %q does not match historical project %q", input.Project, project.Project)
	}
	if input.GeneratedAt.IsZero() {
		return errors.New("report v1 generatedAt is required")
	}
	if !legacyDigestPattern.MatchString(input.ConfigDigest) {
		return errors.New("report v1 configDigest is invalid")
	}
	if !input.FailOn.Valid() {
		return errors.New("report v1 failOn is invalid")
	}
	return nil
}

func historicalWaiverRule() sdk.Rule {
	return sdk.Rule{ID: "hoolicy.waivers", Title: "Hoolicy policy lifecycle", Remediation: "Correct or remove the invalid policy metadata.", Severity: sdk.SeverityError}
}

func historicalWaiverFinding(project *config.Project, message, key string) sdk.Finding {
	rule := historicalWaiverRule()
	finding := sdk.Finding{RuleID: rule.ID, Title: rule.Title, Message: message, Remediation: rule.Remediation, Severity: rule.Severity, Location: sdk.Location{Path: project.Waivers, Line: 1, Column: 1}, Key: key}
	finding.Fingerprint = legacyFindingFingerprint(finding)
	return finding
}

type legacyWaiverFile struct {
	Version int            `yaml:"version"`
	Waivers []legacyWaiver `yaml:"waivers"`
}

// legacyWaiver deliberately models the v1 file instead of reusing the
// current config type. The migration must decode the schema that produced
// the report, not whatever fields a newer config happens to add.
type legacyWaiver struct {
	ID           string      `yaml:"id"`
	Rule         string      `yaml:"rule"`
	Fingerprints []string    `yaml:"fingerprints,omitempty"`
	Paths        []string    `yaml:"paths,omitempty"`
	Reason       string      `yaml:"reason"`
	Owner        string      `yaml:"owner"`
	Ticket       string      `yaml:"ticket"`
	Approver     string      `yaml:"approver,omitempty"`
	Created      config.Date `yaml:"created"`
	Expires      config.Date `yaml:"expires"`
}

type historicalWaiver struct {
	legacy   config.Waiver
	migrated config.Waiver
}

type historicalWaiverState struct {
	waived   bool
	waiverID string
}

func loadHistoricalWaivers(project *config.Project, generatedAt time.Time, findings []sdk.Finding) ([]historicalWaiver, []sdk.Finding, error) {
	waivers := []historicalWaiver{}
	lifecycle := []sdk.Finding{}
	_, path, err := safepath.Existing(project.Root, project.Waivers)
	if errors.Is(err, os.ErrNotExist) {
		return waivers, lifecycle, nil
	}
	if err != nil {
		lifecycle = append(lifecycle, historicalWaiverFinding(project, "Waiver path is unsafe: "+err.Error(), "path"))
		return waivers, lifecycle, nil
	}
	var file legacyWaiverFile
	if err := config.LoadYAMLStrict(path, &file); err != nil {
		lifecycle = append(lifecycle, historicalWaiverFinding(project, "Waiver file is invalid: "+err.Error(), "parse"))
		return waivers, lifecycle, nil
	}
	if file.Version != 1 {
		lifecycle = append(lifecycle, historicalWaiverFinding(project, fmt.Sprintf("Waiver file is invalid: %s: version must be 1", path), "parse"))
		return waivers, lifecycle, nil
	}
	seen := make(map[string]struct{}, len(file.Waivers))
	for _, legacy := range file.Waivers {
		if _, exists := seen[legacy.ID]; exists {
			lifecycle = append(lifecycle, historicalWaiverFinding(project, "Duplicate waiver ID: "+legacy.ID, legacy.ID))
			continue
		}
		seen[legacy.ID] = struct{}{}
		legacyWaiver := config.Waiver{
			ID: legacy.ID, Rule: legacy.Rule,
			Fingerprints: append([]string(nil), legacy.Fingerprints...),
			Paths:        append([]string(nil), legacy.Paths...),
			Reason:       legacy.Reason, Owner: legacy.Owner, Ticket: legacy.Ticket, Approver: legacy.Approver,
			Created: legacy.Created, Expires: legacy.Expires,
		}
		if err := validateLegacyWaiver(legacyWaiver, generatedAt); err != nil {
			lifecycle = append(lifecycle, historicalWaiverFinding(project, "Invalid waiver "+legacy.ID+": "+err.Error(), legacy.ID))
			continue
		}
		matches := make([]sdk.Finding, 0)
		for _, finding := range findings {
			if strings.HasPrefix(finding.RuleID, "hoolicy.") || finding.RuleID != legacyWaiver.Rule {
				continue
			}
			if legacyWaiverMatches(legacyWaiver, finding) {
				matches = append(matches, finding)
			}
		}
		if len(matches) == 0 {
			lifecycle = append(lifecycle, historicalWaiverFinding(project, "Stale waiver matches no current finding: "+legacy.ID, legacy.ID))
		}
		migrated, keep := migrateHistoricalWaiver(legacyWaiver, matches, generatedAt)
		if keep {
			waivers = append(waivers, historicalWaiver{legacy: legacyWaiver, migrated: migrated})
		}
	}
	return waivers, lifecycle, nil
}

func validateLegacyWaiver(waiver config.Waiver, now time.Time) error {
	var problems []string
	if !legacyRuleIDPattern.MatchString(waiver.ID) {
		problems = append(problems, "id is invalid")
	}
	if !legacyRuleIDPattern.MatchString(waiver.Rule) {
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
		}
		if err := validateLegacyRelativePath(path); err != nil {
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

func validateLegacyRelativePath(path string) error {
	if path == "" {
		return nil
	}
	if filepath.IsAbs(path) {
		return errors.New("absolute paths are forbidden")
	}
	clean := filepath.Clean(path)
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return errors.New("path escapes repository root")
	}
	return nil
}

func migrateHistoricalWaiver(waiver config.Waiver, matches []sdk.Finding, generatedAt time.Time) (config.Waiver, bool) {
	migrated := waiver
	migrated.Fingerprints = append([]string(nil), waiver.Fingerprints...)
	migrated.Paths = nil
	for _, finding := range matches {
		if !containsString(migrated.Fingerprints, finding.Fingerprint) {
			migrated.Fingerprints = append(migrated.Fingerprints, finding.Fingerprint)
		}
	}
	if len(matches) == 0 {
		migrated.Paths = make([]string, 0, len(waiver.Paths))
		for _, path := range waiver.Paths {
			migrated.Paths = append(migrated.Paths, strings.ReplaceAll(filepath.ToSlash(path), `\`, "/"))
		}
	}
	if err := config.ValidateWaiver(migrated, generatedAt); err == nil {
		return migrated, true
	}
	// A legacy path can be valid under v1 while being intentionally too broad
	// for v2. Exact historical fingerprints retain the waiver's accountable
	// metadata without carrying that unsafe scope into the v2 report.
	if len(migrated.Fingerprints) != 0 {
		migrated.Paths = nil
		if err := config.ValidateWaiver(migrated, generatedAt); err == nil {
			return migrated, true
		}
	}
	return config.Waiver{}, false
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func verifyHistoricalWaiverFindings(findings []legacyFinding, expected []sdk.Finding) error {
	expectedByFingerprint := make(map[string][]sdk.Finding, len(expected))
	for _, finding := range expected {
		expectedByFingerprint[finding.Fingerprint] = append(expectedByFingerprint[finding.Fingerprint], finding)
	}
	for _, finding := range findings {
		if finding.RuleID != "hoolicy.waivers" {
			continue
		}
		candidates := expectedByFingerprint[finding.Fingerprint]
		match := -1
		for index, candidate := range candidates {
			if finding.Message == candidate.Message && finding.Title == candidate.Title && finding.Remediation == candidate.Remediation && finding.Severity == candidate.Severity && finding.Location == candidate.Location && finding.Key == candidate.Key {
				match = index
				break
			}
		}
		if match < 0 {
			return fmt.Errorf("report contains unexpected historical waiver finding %s", finding.Message)
		}
		candidates = append(candidates[:match], candidates[match+1:]...)
		if len(candidates) == 0 {
			delete(expectedByFingerprint, finding.Fingerprint)
		} else {
			expectedByFingerprint[finding.Fingerprint] = candidates
		}
	}
	for _, candidates := range expectedByFingerprint {
		if len(candidates) != 0 {
			return errors.New("report is missing historical waiver lifecycle finding")
		}
	}
	return nil
}

func legacyWaiverMatches(waiver config.Waiver, finding sdk.Finding) bool {
	for _, fingerprint := range waiver.Fingerprints {
		if fingerprint == finding.Fingerprint {
			return true
		}
	}
	if finding.Location.Path == "" || len(waiver.Paths) == 0 {
		return false
	}
	matched, _ := repository.Matches(finding.Location.Path, waiver.Paths)
	return matched
}
func replayHistoricalWaiverState(findings []sdk.Finding, waivers []historicalWaiver) map[string]historicalWaiverState {
	state := make(map[string]historicalWaiverState, len(findings))
	for _, waiver := range waivers {
		for _, finding := range findings {
			if strings.HasPrefix(finding.RuleID, "hoolicy.") || finding.RuleID != waiver.legacy.Rule {
				continue
			}
			if legacyWaiverMatches(waiver.legacy, finding) {
				state[finding.Fingerprint] = historicalWaiverState{waived: true, waiverID: waiver.legacy.ID}
			}
		}
	}
	return state
}

func summarizeLegacy(findings []sdk.Finding, failOn sdk.Severity, ruleCount int) legacySummary {
	var summary legacySummary
	summary.Rules = ruleCount
	for _, finding := range findings {
		switch finding.Severity {
		case sdk.SeverityError:
			summary.Errors++
		case sdk.SeverityWarning:
			summary.Warnings++
		case sdk.SeverityInfo:
			summary.Info++
		}
		if finding.Waived {
			summary.Waived++
		} else if finding.Severity.Rank() >= failOn.Rank() {
			summary.Blocking++
		}
	}
	return summary
}

// MigrateJSON converts a strict report v1 document using the exact active
// policy state that produced it.
func MigrateJSON(path string, project *config.Project, rules []sdk.Rule, expectedConfigDigest string) (*engine.Report, error) {
	if project == nil {
		return nil, errors.New("historical project configuration is required")
	}
	data, err := readReportFile(path)
	if err != nil {
		return nil, err
	}
	input, err := decodeLegacy(data, path)
	if err != nil {
		return nil, err
	}
	if err := validateLegacyEnvelope(input, project); err != nil {
		return nil, err
	}
	historicalDigest, err := LegacyProjectDigest(project, rules)
	if err != nil {
		return nil, fmt.Errorf("historical project digest: %w", err)
	}
	if expectedConfigDigest != "" && expectedConfigDigest != historicalDigest {
		return nil, fmt.Errorf("provided historical project digest %s does not match calculated digest %s", expectedConfigDigest, historicalDigest)
	}
	if input.ConfigDigest != historicalDigest {
		return nil, fmt.Errorf("report config digest %s does not match historical project digest %s", input.ConfigDigest, historicalDigest)
	}
	currentPolicyDigest, err := engine.ProjectDigest(project, rules)
	if err != nil {
		return nil, fmt.Errorf("current project digest: %w", err)
	}
	historical := legacyEngineReport(input)
	waivers, lifecycle, err := loadHistoricalWaivers(project, input.GeneratedAt, historical.Findings)
	if err != nil {
		return nil, err
	}
	if err := verifyHistoricalWaiverFindings(input.Findings, lifecycle); err != nil {
		return nil, err
	}
	waiverByID := make(map[string]config.Waiver, len(waivers))
	legacyState := replayHistoricalWaiverState(historical.Findings, waivers)
	for _, waiver := range waivers {
		waiverByID[waiver.migrated.ID] = waiver.migrated
	}
	if input.Summary != summarizeLegacy(historical.Findings, input.FailOn, len(rules)) {
		return nil, errors.New("report v1 summary does not match findings")
	}
	findings := make([]sdk.Finding, 0, len(historical.Findings))
	migratedFingerprints := make(map[string]struct{}, len(historical.Findings))
	for _, legacy := range historical.Findings {
		rule, exists := findMigrationRule(legacy.RuleID, rules)
		if !exists {
			return nil, fmt.Errorf("report finding uses unknown rule %s", legacy.RuleID)
		}
		if !legacy.Severity.Valid() || legacy.RuleID == "" || !fingerprintPattern.MatchString(legacy.Fingerprint) {
			return nil, fmt.Errorf("report finding %s has invalid v1 finding fields", legacy.RuleID)
		}
		if legacy.Fingerprint != legacyFindingFingerprint(legacy) {
			return nil, fmt.Errorf("report finding %s has invalid v1 fingerprint", legacy.RuleID)
		}
		if legacy.Title != rule.Title || legacy.Remediation != rule.Remediation || legacy.Severity != rule.Severity || legacy.Pack != rule.Pack {
			return nil, fmt.Errorf("report finding %s does not match active rule metadata", legacy.RuleID)
		}
		finding := sdk.Finding{
			Message: legacy.Message, Location: legacy.Location, Key: legacy.Key,
			Fix: legacy.Fix, Properties: legacy.Properties,
		}
		finding.Finalize(rule)
		if legacy.RuleID == "hoolicy.waivers" {
			for suffix := 2; ; suffix++ {
				if _, exists := migratedFingerprints[finding.Fingerprint]; !exists {
					break
				}
				finding.Key = fmt.Sprintf("%s#%d", legacy.Key, suffix)
				finding.Finalize(rule)
			}
		}
		if _, exists := migratedFingerprints[finding.Fingerprint]; exists {
			return nil, fmt.Errorf("report contains duplicate migrated finding fingerprint %s", finding.Fingerprint)
		}
		migratedFingerprints[finding.Fingerprint] = struct{}{}
		expectedWaiver := legacyState[legacy.Fingerprint]
		if legacy.Waived != expectedWaiver.waived || legacy.WaiverID != expectedWaiver.waiverID {
			return nil, fmt.Errorf("report finding %s does not match historical waiver state", legacy.RuleID)
		}
		if expectedWaiver.waived {
			waiver, exists := waiverByID[expectedWaiver.waiverID]
			if !exists || waiver.Rule != legacy.RuleID {
				return nil, fmt.Errorf("report finding %s references invalid waiver %s", legacy.RuleID, expectedWaiver.waiverID)
			}
			finding.Waived = true
			finding.WaiverID = expectedWaiver.waiverID
			finding.State = sdk.FindingWaived
			finding.StateSource = "waiver"
		} else {
			finding.State = sdk.FindingNew
			finding.StateSource = ""
		}
		findings = append(findings, finding)
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Fingerprint != findings[j].Fingerprint {
			return findings[i].Fingerprint < findings[j].Fingerprint
		}
		return findings[i].RuleID < findings[j].RuleID
	})
	migratedWaivers := make([]config.Waiver, 0, len(waivers))
	for _, waiver := range waivers {
		migratedWaivers = append(migratedWaivers, waiver.migrated)
	}
	result := &engine.Report{
		ReportVersion: 2, Tool: input.Tool, Project: input.Project, GeneratedAt: input.GeneratedAt,
		ConfigDigest: input.ConfigDigest, PolicyDigest: currentPolicyDigest, Git: input.Git, FailOn: input.FailOn,
		Findings: findings, Waivers: migratedWaivers, Changes: []engine.Change{},
		Metrics: engine.EvaluationMetrics{Rules: []engine.RuleMetric{}},
	}
	result.Summary = summarizeMigrated(findings, input.FailOn, len(rules))
	if err := ValidateV2(result, project, rules); err != nil {
		return nil, err
	}
	return result, nil
}

func findMigrationRule(id string, rules []sdk.Rule) (sdk.Rule, bool) {
	for _, rule := range rules {
		if rule.ID == id {
			return rule, true
		}
	}
	if id == "hoolicy.waivers" {
		return historicalWaiverRule(), true
	}
	if id == "hoolicy.baseline" {
		return sdk.Rule{ID: id, Title: "Hoolicy policy lifecycle", Remediation: "Correct or remove the invalid policy metadata.", Severity: sdk.SeverityError}, true
	}
	return sdk.Rule{}, false
}

func summarizeMigrated(findings []sdk.Finding, failOn sdk.Severity, ruleCount int) engine.Summary {
	var summary engine.Summary
	summary.Rules = ruleCount
	for _, finding := range findings {
		switch finding.Severity {
		case sdk.SeverityError:
			summary.Errors++
		case sdk.SeverityWarning:
			summary.Warnings++
		case sdk.SeverityInfo:
			summary.Info++
		}
		if finding.Waived {
			summary.Waived++
		} else {
			if finding.State == sdk.FindingExisting {
				summary.Existing++
			} else {
				summary.New++
			}
			if finding.State != sdk.FindingExisting && finding.Severity.Rank() >= failOn.Rank() {
				summary.Blocking++
			}
		}
	}
	return summary
}

// ValidateV2 verifies the complete report envelope, finding identity, waiver
// state, and derived summary.
func ValidateV2(input *engine.Report, project *config.Project, rules []sdk.Rule) error {
	if input == nil || project == nil || input.ReportVersion != 2 || input.Tool.Name != "hoolicy" || strings.TrimSpace(input.Tool.Version) == "" || input.Project == "" || input.Project != project.Project || input.GeneratedAt.IsZero() || !legacyDigestPattern.MatchString(input.ConfigDigest) || !legacyDigestPattern.MatchString(input.PolicyDigest) || !input.FailOn.Valid() || input.Findings == nil || input.Waivers == nil || input.Metrics.Rules == nil || input.Git.CommitSubjects == nil {
		return errors.New("report does not satisfy the version 2 envelope")
	}
	currentDigest, err := engine.ProjectDigest(project, rules)
	if err != nil || input.PolicyDigest != currentDigest {
		return errors.New("report policy digest does not match project")
	}
	if input.ConfigDigest != currentDigest {
		legacyDigest, legacyErr := LegacyProjectDigest(project, rules)
		if legacyErr != nil || input.ConfigDigest != legacyDigest {
			return errors.New("report config digest does not match project")
		}
	}
	if input.Metrics.Files < 0 || input.Metrics.Bytes < 0 || input.Metrics.DurationMilliseconds < 0 || input.Metrics.InputCacheHits < 0 || input.Metrics.ParseCacheHits < 0 {
		return errors.New("report metrics contain negative values")
	}
	for _, metric := range input.Metrics.Rules {
		if metric.RuleID == "" || metric.Inputs < 0 || metric.Findings < 0 || metric.DurationMilliseconds < 0 || metric.InputCacheHits < 0 || metric.ParseCacheHits < 0 {
			return errors.New("report contains invalid rule metrics")
		}
	}
	byID := make(map[string]sdk.Rule, len(rules))
	for _, rule := range rules {
		byID[rule.ID] = rule
	}
	waiverByID := make(map[string]config.Waiver, len(input.Waivers))
	for _, waiver := range input.Waivers {
		if _, exists := waiverByID[waiver.ID]; exists {
			return fmt.Errorf("report contains duplicate waiver %s", waiver.ID)
		}
		if err := config.ValidateWaiverForProject(waiver, input.GeneratedAt, project.RequireWaiverApprover); err != nil {
			return fmt.Errorf("report waiver %s: %w", waiver.ID, err)
		}
		waiverByID[waiver.ID] = waiver
	}
	seen := make(map[string]struct{}, len(input.Findings))
	var summary engine.Summary
	for _, finding := range input.Findings {
		rule, exists := byID[finding.RuleID]
		if !exists && (finding.RuleID == "hoolicy.waivers" || finding.RuleID == "hoolicy.baseline") {
			rule = sdk.Rule{ID: finding.RuleID, Title: "Hoolicy policy lifecycle", Remediation: "Correct or remove the invalid policy metadata.", Severity: sdk.SeverityError}
			exists = true
		}
		if !exists {
			return fmt.Errorf("report finding uses unknown rule %s", finding.RuleID)
		}
		if finding.Location.Line < 0 || finding.Location.Column < 0 || !fingerprintPattern.MatchString(finding.Fingerprint) || !legacyDigestPattern.MatchString(finding.PolicyDigest) || !legacyDigestPattern.MatchString(finding.FindingDigest) {
			return fmt.Errorf("report finding %s has invalid fields", finding.RuleID)
		}
		expected := finding
		expected.Finalize(rule)
		expectedControls, _ := json.Marshal(expected.Controls)
		actualControls, _ := json.Marshal(finding.Controls)
		if finding.Title != expected.Title || finding.Remediation != expected.Remediation || finding.Severity != expected.Severity || finding.Pack != expected.Pack || !bytes.Equal(expectedControls, actualControls) || expected.Fingerprint != finding.Fingerprint || expected.PolicyDigest != finding.PolicyDigest || expected.FindingDigest != finding.FindingDigest {
			return fmt.Errorf("report finding %s has invalid identity", finding.RuleID)
		}
		if _, exists := seen[finding.Fingerprint]; exists {
			return fmt.Errorf("report contains duplicate finding fingerprint %s", finding.Fingerprint)
		}
		seen[finding.Fingerprint] = struct{}{}
		if finding.Waived {
			if finding.State != sdk.FindingWaived || finding.StateSource != "waiver" || finding.WaiverID == "" {
				return fmt.Errorf("report finding %s has inconsistent waived state", finding.RuleID)
			}
			waiver, exists := waiverByID[finding.WaiverID]
			if !exists || waiver.Rule != finding.RuleID {
				return fmt.Errorf("report finding %s references invalid waiver %s", finding.RuleID, finding.WaiverID)
			}
			summary.Waived++
		} else {
			if finding.State != sdk.FindingNew && finding.State != sdk.FindingExisting {
				return fmt.Errorf("report finding %s has invalid state %s", finding.RuleID, finding.State)
			}
			if finding.WaiverID != "" || finding.StateSource == "waiver" {
				return fmt.Errorf("report finding %s has unexpected waiver metadata", finding.RuleID)
			}
			if finding.State == sdk.FindingExisting {
				summary.Existing++
				if finding.StateSource != "baseline" && finding.StateSource != "git" {
					return fmt.Errorf("report finding %s has invalid existing state source", finding.RuleID)
				}
			} else {
				summary.New++
				if finding.StateSource != "" {
					return fmt.Errorf("report finding %s has invalid new state source", finding.RuleID)
				}
			}
			if finding.State != sdk.FindingExisting && finding.Severity.Rank() >= input.FailOn.Rank() {
				summary.Blocking++
			}
		}
		switch finding.Severity {
		case sdk.SeverityError:
			summary.Errors++
		case sdk.SeverityWarning:
			summary.Warnings++
		case sdk.SeverityInfo:
			summary.Info++
		}
	}
	summary.Rules = len(rules)
	if input.Summary != summary {
		return errors.New("report summary does not match findings")
	}
	return nil
}

func LoadJSON(path string) (*engine.Report, error) {
	data, err := readReportFile(path)
	if err != nil {
		return nil, err
	}
	var version struct {
		ReportVersion int `json:"reportVersion"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&version); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if version.ReportVersion == 1 {
		legacy, err := decodeLegacy(data, path)
		if err != nil {
			return nil, err
		}
		return legacyEngineReport(legacy), nil
	}
	var input engine.Report
	decoder = json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("%s: exactly one JSON value is required", path)
		}
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if input.ReportVersion < 1 || input.ReportVersion > 2 {
		return nil, fmt.Errorf("%s: unsupported report version %d", path, input.ReportVersion)
	}
	return &input, nil
}

func readReportFile(path string) ([]byte, error) {
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if pathInfo.Mode()&os.ModeSymlink != 0 || !pathInfo.Mode().IsRegular() || pathInfo.Size() > MaxReportFileSize {
		return nil, fmt.Errorf("%s: report must be a regular file no larger than %d bytes", path, MaxReportFileSize)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(opened, pathInfo) || opened.Size() > MaxReportFileSize {
		return nil, fmt.Errorf("%s: report changed, is not regular, or exceeds %d bytes", path, MaxReportFileSize)
	}
	data, err := io.ReadAll(io.LimitReader(file, MaxReportFileSize+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > MaxReportFileSize || int64(len(data)) != opened.Size() {
		return nil, fmt.Errorf("%s: report changed or exceeds %d bytes", path, MaxReportFileSize)
	}
	return data, nil
}

func Compare(before, after *engine.Report) Diff {
	diff := Diff{BeforePolicyDigest: fallbackDigest(before), AfterPolicyDigest: fallbackDigest(after)}
	left := make(map[string]sdk.Finding, len(before.Findings))
	right := make(map[string]sdk.Finding, len(after.Findings))
	for _, finding := range before.Findings {
		left[finding.Fingerprint] = finding
	}
	for _, finding := range after.Findings {
		right[finding.Fingerprint] = finding
	}
	for fingerprint, finding := range right {
		previous, exists := left[fingerprint]
		if !exists {
			diff.Added = append(diff.Added, finding)
			continue
		}
		if previous.PolicyDigest != finding.PolicyDigest || previous.FindingDigest != finding.FindingDigest || previous.State != finding.State || previous.Waived != finding.Waived {
			diff.Changed = append(diff.Changed, FindingChange{Fingerprint: fingerprint, Before: previous, After: finding})
		}
	}
	for fingerprint, finding := range left {
		if _, exists := right[fingerprint]; !exists {
			diff.Removed = append(diff.Removed, finding)
		}
	}
	sort.Slice(diff.Added, func(i, j int) bool { return findingLess(diff.Added[i], diff.Added[j]) })
	sort.Slice(diff.Removed, func(i, j int) bool { return findingLess(diff.Removed[i], diff.Removed[j]) })
	sort.Slice(diff.Changed, func(i, j int) bool { return diff.Changed[i].Fingerprint < diff.Changed[j].Fingerprint })
	diff.Waivers = compareWaivers(before, after)
	return diff
}

func compareWaivers(before, after *engine.Report) WaiverDiff {
	result := WaiverDiff{Added: []config.Waiver{}, Removed: []config.Waiver{}, Renewed: []WaiverRenewal{}, ScopeGrown: []WaiverScopeGrowth{}, Expired: []config.Waiver{}}
	left := make(map[string]config.Waiver, len(before.Waivers))
	right := make(map[string]config.Waiver, len(after.Waivers))
	for _, waiver := range before.Waivers {
		left[waiver.ID] = waiver
	}
	for _, waiver := range after.Waivers {
		right[waiver.ID] = waiver
	}
	for id, waiver := range right {
		previous, exists := left[id]
		if !exists {
			result.Added = append(result.Added, waiver)
		} else {
			if waiver.Expires.After(previous.Expires.Time) {
				result.Renewed = append(result.Renewed, WaiverRenewal{ID: id, BeforeExpires: previous.Expires, AfterExpires: waiver.Expires})
			}
			growth := WaiverScopeGrowth{ID: id, AddedFingerprints: addedStrings(previous.Fingerprints, waiver.Fingerprints), AddedPaths: addedStrings(previous.Paths, waiver.Paths)}
			if len(growth.AddedFingerprints) > 0 || len(growth.AddedPaths) > 0 {
				result.ScopeGrown = append(result.ScopeGrown, growth)
			}
		}
		if !waiver.Expires.IsZero() && !after.GeneratedAt.IsZero() && after.GeneratedAt.UTC().Truncate(24*time.Hour).After(waiver.Expires.Time) {
			result.Expired = append(result.Expired, waiver)
		}
	}
	for id, waiver := range left {
		if _, exists := right[id]; !exists {
			result.Removed = append(result.Removed, waiver)
		}
	}
	sort.Slice(result.Added, func(i, j int) bool { return result.Added[i].ID < result.Added[j].ID })
	sort.Slice(result.Removed, func(i, j int) bool { return result.Removed[i].ID < result.Removed[j].ID })
	sort.Slice(result.Expired, func(i, j int) bool { return result.Expired[i].ID < result.Expired[j].ID })
	sort.Slice(result.Renewed, func(i, j int) bool { return result.Renewed[i].ID < result.Renewed[j].ID })
	sort.Slice(result.ScopeGrown, func(i, j int) bool { return result.ScopeGrown[i].ID < result.ScopeGrown[j].ID })
	return result
}

func addedStrings(before, after []string) []string {
	known := make(map[string]bool, len(before))
	for _, value := range before {
		known[value] = true
	}
	result := []string{}
	for _, value := range after {
		if !known[value] {
			result = append(result, value)
		}
	}
	sort.Strings(result)
	return result
}

func fallbackDigest(input *engine.Report) string {
	if input.PolicyDigest != "" {
		return input.PolicyDigest
	}
	return input.ConfigDigest
}

func findingLess(left, right sdk.Finding) bool {
	if left.RuleID != right.RuleID {
		return left.RuleID < right.RuleID
	}
	return left.Fingerprint < right.Fingerprint
}

func WriteDiff(writer io.Writer, format string, diff Diff) error {
	if format == "json" {
		encoder := json.NewEncoder(writer)
		encoder.SetIndent("", "  ")
		encoder.SetEscapeHTML(false)
		return encoder.Encode(diff)
	}
	if format != "" && format != "text" {
		return fmt.Errorf("unknown report diff format %q", format)
	}
	if diff.BeforePolicyDigest != diff.AfterPolicyDigest {
		fmt.Fprintf(writer, "POLICY %s -> %s\n", diff.BeforePolicyDigest, diff.AfterPolicyDigest)
	}
	for _, finding := range diff.Added {
		fmt.Fprintf(writer, "ADDED %s %s %s\n", finding.RuleID, shortFingerprint(finding.Fingerprint), singleLine(finding.Message))
	}
	for _, finding := range diff.Removed {
		fmt.Fprintf(writer, "REMOVED %s %s %s\n", finding.RuleID, shortFingerprint(finding.Fingerprint), singleLine(finding.Message))
	}
	for _, change := range diff.Changed {
		fmt.Fprintf(writer, "CHANGED %s %s\n", change.After.RuleID, shortFingerprint(change.Fingerprint))
	}
	for _, waiver := range diff.Waivers.Added {
		fmt.Fprintf(writer, "WAIVER ADDED %s\n", waiver.ID)
	}
	for _, waiver := range diff.Waivers.Removed {
		fmt.Fprintf(writer, "WAIVER REMOVED %s\n", waiver.ID)
	}
	for _, renewal := range diff.Waivers.Renewed {
		fmt.Fprintf(writer, "WAIVER RENEWED %s %s -> %s\n", renewal.ID, renewal.BeforeExpires.Time.Format("2006-01-02"), renewal.AfterExpires.Time.Format("2006-01-02"))
	}
	for _, growth := range diff.Waivers.ScopeGrown {
		fmt.Fprintf(writer, "WAIVER SCOPE-GROWN %s +%d fingerprints +%d paths\n", growth.ID, len(growth.AddedFingerprints), len(growth.AddedPaths))
	}
	for _, waiver := range diff.Waivers.Expired {
		fmt.Fprintf(writer, "WAIVER EXPIRED %s\n", waiver.ID)
	}
	fmt.Fprintf(writer, "\n%d added, %d removed, %d changed; %d waiver changes\n", len(diff.Added), len(diff.Removed), len(diff.Changed), len(diff.Waivers.Added)+len(diff.Waivers.Removed)+len(diff.Waivers.Renewed)+len(diff.Waivers.ScopeGrown)+len(diff.Waivers.Expired))
	return nil
}
