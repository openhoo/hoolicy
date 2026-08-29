package rules

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/openhoo/hoolicy/internal/document"
	"github.com/openhoo/hoolicy/sdk"
)

type ExceptionsLifecycle struct{}

type exceptionsSpec struct {
	Format       string   `yaml:"format,omitempty"`
	Collection   string   `yaml:"collection"`
	IDField      string   `yaml:"idField,omitempty"`
	ReasonField  string   `yaml:"reasonField,omitempty"`
	OwnerField   string   `yaml:"ownerField,omitempty"`
	TicketField  string   `yaml:"ticketField,omitempty"`
	CreatedField string   `yaml:"createdField,omitempty"`
	ExpiresField string   `yaml:"expiresField,omitempty"`
	Required     []string `yaml:"required,omitempty"`
	MaximumDays  int      `yaml:"maximumDays,omitempty"`
	Message      string   `yaml:"message"`
}

func (ExceptionsLifecycle) Validate(rule sdk.Rule) error {
	if err := requireFiles(rule); err != nil {
		return err
	}
	var spec exceptionsSpec
	if err := decodeSpec(rule, &spec); err != nil {
		return err
	}
	defaultsForExceptions(&spec)
	if spec.Collection == "" {
		return fmt.Errorf("rule %s: exceptions.lifecycle requires collection", rule.ID)
	}
	if spec.MaximumDays < 1 || spec.MaximumDays > 365 {
		return fmt.Errorf("rule %s: maximumDays must be between 1 and 365", rule.ID)
	}
	known := map[string]bool{"id": true, "reason": true, "owner": true, "ticket": true, "created": true, "expires": true}
	for _, field := range spec.Required {
		if !known[field] {
			return fmt.Errorf("rule %s: unknown required exception field %q", rule.ID, field)
		}
	}
	return nil
}

func (ExceptionsLifecycle) Evaluate(_ context.Context, input sdk.EvalContext, rule sdk.Rule) ([]sdk.Finding, error) {
	var spec exceptionsSpec
	if err := decodeSpec(rule, &spec); err != nil {
		return nil, err
	}
	defaultsForExceptions(&spec)
	files, err := input.Repository.Match(rule.Files, rule.Exclude)
	if err != nil {
		return nil, err
	}
	message := spec.Message
	if message == "" {
		message = "Policy exception is incomplete, overlong, or expired"
	}
	var findings []sdk.Finding
	for _, file := range files {
		documents, hit, parseErr := document.ParseCached(file, spec.Format)
		if parseErr != nil {
			return nil, parseErr
		}
		if hit && input.Metrics != nil {
			input.Metrics.ParseCacheHits++
		}
		for _, item := range documents {
			items, err := inspectExceptionDocument(rule, file.Path, item, spec, message, input.Now)
			if err != nil {
				return nil, err
			}
			findings = append(findings, items...)
		}
	}
	return findings, nil
}

func inspectExceptionDocument(rule sdk.Rule, path string, item document.Document, spec exceptionsSpec, message string, now time.Time) ([]sdk.Finding, error) {
	collection, found := lookupDotted(item.Data, spec.Collection)
	if !found {
		return []sdk.Finding{finding(rule, message+": collection "+spec.Collection+" is missing", path, "collection", item.Line, item.Column)}, nil
	}
	entries, ok := collection.([]any)
	if !ok {
		return nil, fmt.Errorf("%s: collection %s must be a list", path, spec.Collection)
	}
	seenIDs := make(map[string]bool)
	var findings []sdk.Finding
	for index, raw := range entries {
		entry, ok := raw.(map[string]any)
		if !ok {
			findings = append(findings, finding(rule, message+": exception must be an object", path, fmt.Sprintf("entry:%d", index), item.Line, item.Column))
			continue
		}
		id := strings.TrimSpace(fmt.Sprint(entry[spec.IDField]))
		key := id
		if key == "" || key == "<nil>" {
			key = fmt.Sprintf("entry:%d", index)
		}
		problems := exceptionProblems(entry, id, seenIDs, spec, now)
		if len(problems) > 0 {
			findings = append(findings, finding(rule, message+": "+strings.Join(problems, "; "), path, key, item.Line, item.Column))
		}
	}
	return findings, nil
}

func exceptionProblems(entry map[string]any, id string, seenIDs map[string]bool, spec exceptionsSpec, now time.Time) []string {
	var problems []string
	if id == "" || id == "<nil>" {
		problems = append(problems, "id is missing")
	} else if seenIDs[id] {
		problems = append(problems, "id is duplicated")
	}
	seenIDs[id] = true
	fields := map[string]string{
		"id": spec.IDField, "reason": spec.ReasonField, "owner": spec.OwnerField,
		"ticket": spec.TicketField, "created": spec.CreatedField, "expires": spec.ExpiresField,
	}
	for _, required := range spec.Required {
		if value := strings.TrimSpace(fmt.Sprint(entry[fields[required]])); value == "" || value == "<nil>" {
			problems = append(problems, required+" is missing")
		}
	}
	if value := strings.TrimSpace(fmt.Sprint(entry[spec.ReasonField])); contains(spec.Required, "reason") && len(value) < 20 {
		problems = append(problems, "reason must contain at least 20 characters")
	}
	if contains(spec.Required, "ticket") {
		ticket, err := url.Parse(fmt.Sprint(entry[spec.TicketField]))
		if err != nil || ticket.Scheme != "https" || ticket.Host == "" {
			problems = append(problems, "ticket must be an absolute HTTPS URL")
		}
	}
	created, createdErr := parseDateValue(entry[spec.CreatedField])
	expires, expiresErr := parseDateValue(entry[spec.ExpiresField])
	if contains(spec.Required, "created") && createdErr != nil {
		problems = append(problems, "created must be YYYY-MM-DD")
	}
	if contains(spec.Required, "expires") && expiresErr != nil {
		problems = append(problems, "expires must be YYYY-MM-DD")
	}
	if createdErr == nil && expiresErr == nil {
		problems = append(problems, exceptionDateProblems(created, expires, spec.MaximumDays, now)...)
	}
	return problems
}

func exceptionDateProblems(created, expires time.Time, maximumDays int, now time.Time) []string {
	var problems []string
	if expires.Before(created) {
		problems = append(problems, "expires precedes created")
	}
	if expires.Sub(created) > time.Duration(maximumDays)*24*time.Hour {
		problems = append(problems, fmt.Sprintf("lifetime exceeds %d days", maximumDays))
	}
	if now.UTC().Truncate(24 * time.Hour).After(expires) {
		problems = append(problems, "exception is expired")
	}
	return problems
}

func defaultsForExceptions(spec *exceptionsSpec) {
	if spec.IDField == "" {
		spec.IDField = "id"
	}
	if spec.ReasonField == "" {
		spec.ReasonField = "reason"
	}
	if spec.OwnerField == "" {
		spec.OwnerField = "owner"
	}
	if spec.TicketField == "" {
		spec.TicketField = "ticket"
	}
	if spec.CreatedField == "" {
		spec.CreatedField = "created"
	}
	if spec.ExpiresField == "" {
		spec.ExpiresField = "expires"
	}
	if len(spec.Required) == 0 {
		spec.Required = []string{"id", "reason", "owner", "ticket", "created", "expires"}
	}
	if spec.MaximumDays == 0 {
		spec.MaximumDays = 90
	}
}

func lookupDotted(value any, path string) (any, bool) {
	current := value
	for _, segment := range strings.Split(path, ".") {
		object, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		current, ok = object[segment]
		if !ok {
			return nil, false
		}
	}
	return current, true
}

func parseDateValue(value any) (time.Time, error) {
	switch current := value.(type) {
	case time.Time:
		return current.UTC(), nil
	case string:
		return time.Parse("2006-01-02", current)
	default:
		return time.Time{}, fmt.Errorf("not a date")
	}
}

func contains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
