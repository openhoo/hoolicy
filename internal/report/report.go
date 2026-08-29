package report

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"html"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/openhoo/hoolicy/internal/config"
	"github.com/openhoo/hoolicy/internal/engine"
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

func LoadJSON(path string) (*engine.Report, error) {
	data, err := readReportFile(path)
	if err != nil {
		return nil, err
	}
	var input engine.Report
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
