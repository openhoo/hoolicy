package report

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"

	"github.com/openhoo/hoolicy/internal/engine"
	"github.com/openhoo/hoolicy/sdk"
)

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
	default:
		return fmt.Errorf("unknown report format %q", format)
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
		}
		if color {
			label = colorLabel(label, item)
		}
		location := item.Location.Path
		if location != "" && item.Location.Line > 0 {
			location += fmt.Sprintf(":%d:%d", item.Location.Line, item.Location.Column)
		}
		if location != "" {
			location += " "
		}
		fmt.Fprintf(writer, "%s %s%s %s\n", label, location, item.RuleID, item.Message)
		fmt.Fprintf(writer, "  Fix: %s\n", item.Remediation)
		if item.Waived {
			fmt.Fprintf(writer, "  Waiver: %s\n", item.WaiverID)
		}
	}
	fmt.Fprintf(writer, "\n%d rules, %d findings, %d waived, %d blocking\n", report.Summary.Rules, len(report.Findings), report.Summary.Waived, report.Summary.Blocking)
	return nil
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
		if item.Waived {
			caseItem.Skipped = &testSkipped{Message: "Waived by " + item.WaiverID}
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
