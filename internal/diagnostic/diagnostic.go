// Package diagnostic binds operational failures to their policy and phase.
package diagnostic

import (
	"errors"
	"fmt"
	"strings"

	"github.com/openhoo/hoolicy/sdk"
)

type RuleError struct {
	Phase     string
	Rule      sdk.Rule
	Workspace string
	Cause     error
}

type OperationError struct {
	Phase string
	Cause error
}

func (err *OperationError) Error() string { return err.Cause.Error() }
func (err *OperationError) Unwrap() error { return err.Cause }

func (err *RuleError) Error() string {
	message := err.Cause.Error()
	if strings.HasPrefix(message, "rule "+err.Rule.ID+" ") || strings.HasPrefix(message, "rule "+err.Rule.ID+":") {
		return message
	}
	return fmt.Sprintf("rule %s: %s", err.Rule.ID, message)
}
func (err *RuleError) Unwrap() error { return err.Cause }

// Diagnostic is a separate error envelope, never a successful decision report.
type Diagnostic struct {
	Code        string             `json:"code"`
	Phase       string             `json:"phase"`
	Message     string             `json:"message"`
	ExitCode    int                `json:"exitCode"`
	RuleID      string             `json:"ruleId,omitempty"`
	Title       string             `json:"title,omitempty"`
	Workspace   string             `json:"workspace,omitempty"`
	Pack        string             `json:"pack,omitempty"`
	Remediation string             `json:"remediation,omitempty"`
	Policy      *sdk.PolicyContext `json:"policy,omitempty"`
}

func Describe(err error) Diagnostic {
	result := Diagnostic{Code: "execution_failed", Phase: "execution", Message: err.Error(), ExitCode: 2}
	var operationError *OperationError
	if errors.As(err, &operationError) {
		result.Phase, result.Code = operationError.Phase, operationError.Phase+"_failed"
	}
	var ruleError *RuleError
	if errors.As(err, &ruleError) {
		result.Code = "rule_" + ruleError.Phase + "_failed"
		result.Phase = ruleError.Phase
		result.RuleID, result.Title, result.Workspace = ruleError.Rule.ID, ruleError.Rule.Title, ruleError.Workspace
		result.Pack, result.Remediation, result.Policy = ruleError.Rule.Pack, ruleError.Rule.Remediation, ruleError.Rule.PolicyContext()
	}
	return result
}
