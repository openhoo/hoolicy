package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/openhoo/hoolicy/internal/diagnostic"
	"github.com/openhoo/hoolicy/internal/output"
	"github.com/openhoo/hoolicy/sdk"
)

func policyLines(policy *sdk.PolicyContext, remediation string) []string {
	var lines []string
	add := func(label, value string) {
		if value != "" {
			lines = append(lines, label+": "+value)
		}
	}
	if policy != nil {
		add("Checks", policy.Description)
		add("Why", policy.Rationale)
		if explanation := policy.Explanation; explanation != nil {
			add("Expected", explanation.Expectation)
			add("Impact", explanation.Impact)
		}
	}
	add("Fix", remediation)
	if policy != nil && policy.Explanation != nil {
		for index, step := range policy.Explanation.Steps {
			lines = append(lines, fmt.Sprintf("Step %d: %s", index+1, step))
		}
		for _, reference := range policy.Explanation.References {
			lines = append(lines, "Read: "+reference.Title+" — "+reference.URL)
		}
	}
	return lines
}

func findingState(item sdk.Finding) string {
	if item.Waived || item.State == sdk.FindingWaived {
		return string(sdk.FindingWaived)
	}
	if item.State == sdk.FindingExisting {
		return string(sdk.FindingExisting)
	}
	return string(sdk.FindingNew)
}

func findingDisposition(item sdk.Finding, failOn sdk.Severity) string {
	switch findingState(item) {
	case string(sdk.FindingWaived):
		return "accepted by waiver " + item.WaiverID
	case string(sdk.FindingExisting):
		if item.StateSource != "" {
			return "existing; accepted by " + item.StateSource
		}
		return "existing; already reviewed"
	default:
		if item.Severity.Rank() >= failOn.Rank() {
			return "blocking"
		}
		return "non-blocking; below failOn=" + string(failOn)
	}
}

func findingLocation(item sdk.Finding) string {
	location := item.Location.Path
	if location == "" {
		return "repository"
	}
	if item.Location.Line > 0 {
		location += fmt.Sprintf(":%d", item.Location.Line)
		if item.Location.Column > 0 {
			location += fmt.Sprintf(":%d", item.Location.Column)
		}
	}
	return location
}

func countLabel(count int, noun string) string {
	if count != 1 {
		noun += "s"
	}
	return fmt.Sprintf("%d %s", count, noun)
}

// Human output puts actionable groups first and orders occurrences by their
// source locations. Machine formats retain their canonical fingerprint order.
func textFindings(findings []sdk.Finding, failOn sdk.Severity) []sdk.Finding {
	items := append([]sdk.Finding(nil), findings...)
	priority := func(item sdk.Finding) int {
		switch findingState(item) {
		case string(sdk.FindingWaived):
			return 0
		case string(sdk.FindingExisting):
			return 1
		default:
			if item.Severity.Rank() >= failOn.Rank() {
				return 3
			}
			return 2
		}
	}
	groups := make(map[string]int)
	for _, item := range items {
		if rank := priority(item); rank > groups[item.RuleID] {
			groups[item.RuleID] = rank
		}
	}
	sort.SliceStable(items, func(i, j int) bool {
		left, right := items[i], items[j]
		if left.RuleID != right.RuleID {
			if groups[left.RuleID] != groups[right.RuleID] {
				return groups[left.RuleID] > groups[right.RuleID]
			}
			return left.RuleID < right.RuleID
		}
		if priority(left) != priority(right) {
			return priority(left) > priority(right)
		}
		if left.Location.Path != right.Location.Path {
			return left.Location.Path < right.Location.Path
		}
		if left.Location.Line != right.Location.Line {
			return left.Location.Line < right.Location.Line
		}
		if left.Location.Column != right.Location.Column {
			return left.Location.Column < right.Location.Column
		}
		return findingLess(left, right)
	})
	return items
}

// WriteExplanation writes only policy-authored optional guidance. It never
// executes steps, fetches references, or permits terminal control sequences.
func WriteExplanation(writer io.Writer, explanation *sdk.Explanation) error {
	checked := &output.Writer{Destination: writer}
	if explanation != nil {
		policy := &sdk.PolicyContext{Explanation: explanation}
		for _, line := range policyLines(policy, "") {
			fmt.Fprintln(checked, singleLine(line))
		}
	}
	return checked.Err()
}

// WriteDiagnostic emits operational errors separately from decision reports.
// JSON preserves authored data; human-readable output sanitizes terminal text.
func WriteDiagnostic(writer io.Writer, format string, err error) error {
	checked := &output.Writer{Destination: writer}
	detail := diagnostic.Describe(err)
	if format == "json" {
		encodeErr := json.NewEncoder(checked).Encode(struct {
			DiagnosticVersion int                   `json:"diagnosticVersion"`
			Error             diagnostic.Diagnostic `json:"error"`
		}{1, detail})
		if encodeErr != nil {
			return encodeErr
		}
	} else {
		fmt.Fprintf(checked, "hoolicy: %s\n", singleLine(detail.Message))
		fmt.Fprintf(checked, "  Operation failed (exit 2). Phase: %s.\n", singleLine(detail.Phase))
		if detail.RuleID != "" {
			fmt.Fprintf(checked, "  Rule: %s — %s\n", singleLine(detail.RuleID), singleLine(detail.Title))
			source := "project"
			if detail.Pack != "" {
				source = detail.Pack
				if detail.Policy != nil && detail.Policy.PackVersion != "" {
					source += "@" + detail.Policy.PackVersion
				}
			}
			fmt.Fprintf(checked, "  Source: %s\n", singleLine(source))
			if detail.Policy != nil && detail.Policy.Kind != "" {
				fmt.Fprintf(checked, "  Kind: %s\n", singleLine(detail.Policy.Kind))
			}
			if detail.Workspace != "" {
				fmt.Fprintf(checked, "  Workspace: %s\n", singleLine(detail.Workspace))
			}
		}
		fmt.Fprintf(checked, "  Next: %s\n", diagnosticNext(detail.Phase))
		if detail.RuleID != "" {
			fmt.Fprintln(checked, "\n  Policy guidance (no decision was completed):")
			for _, line := range policyLines(detail.Policy, "") {
				fmt.Fprintf(checked, "    %s\n", singleLine(line))
			}
			if detail.Remediation != "" {
				fmt.Fprintf(checked, "    Policy remediation: %s\n", singleLine(detail.Remediation))
			}
			fmt.Fprintf(checked, "  Explain: hoolicy explain %s (use the same --config, if set)\n", singleLine(detail.RuleID))
		}
	}
	return checked.Err()
}

func diagnosticNext(phase string) string {
	switch phase {
	case "arguments":
		return "Correct the reported option or argument; run 'hoolicy check --help' for usage."
	case "configuration":
		return "Correct the reported configuration field, then run 'hoolicy validate'."
	case "pack-resolution":
		return "Review the named pack, vendored files, and lock; run 'hoolicy pack verify'."
	case "validation":
		return "Correct the reported rule kind or specification, then run 'hoolicy validate'."
	case "input":
		return "Check the reported repository path, file access, and resource limits, then rerun the check."
	case "evaluation":
		return "Correct the reported document or evaluation error, then rerun the check."
	case "finding":
		return "Correct the invalid finding returned by the rule implementation, then rerun the check."
	case "output":
		return "Check the report destination and output stream; choose a writable path outside protected policy inputs."
	default:
		return "Resolve the reported operational error, then rerun the command."
	}
}

func findingDetails(item sdk.Finding, failOn sdk.Severity) string {
	lines := []string{"Finding: " + item.Message, "Location: " + findingLocation(item), "Status: " + findingDisposition(item, failOn)}
	if item.Workspace != "" {
		lines = append(lines, "Workspace: "+item.Workspace)
	}
	if item.Owner != "" {
		lines = append(lines, "Owner: "+item.Owner)
	}
	return strings.Join(append(lines, policyLines(item.Policy, item.Remediation)...), "\n")
}
