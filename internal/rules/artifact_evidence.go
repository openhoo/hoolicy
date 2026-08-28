package rules

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/openhoo/hoolicy/internal/evidence"
	"github.com/openhoo/hoolicy/sdk"
)

type ArtifactEvidence struct{}

type artifactEvidenceSpec struct {
	Type             string `yaml:"type"`
	SHA256           string `yaml:"sha256"`
	SubjectDigest    string `yaml:"subjectDigest"`
	RequiredProducer string `yaml:"requiredProducer,omitempty"`
	MaximumAge       string `yaml:"maximumAge,omitempty"`
	MinimumItems     int    `yaml:"minimumItems,omitempty"`
	MaximumFailures  int    `yaml:"maximumFailures,omitempty"`
	Message          string `yaml:"message,omitempty"`
}

var evidenceDigest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

func (ArtifactEvidence) Validate(rule sdk.Rule) error {
	if err := requireFiles(rule); err != nil {
		return err
	}
	var spec artifactEvidenceSpec
	if err := decodeSpec(rule, &spec); err != nil {
		return err
	}
	if len(rule.Files) != 1 {
		return fmt.Errorf("rule %s: artifact.evidence requires exactly one artifact path", rule.ID)
	}
	if spec.Type != "sarif" && spec.Type != "cyclonedx" && spec.Type != "spdx" && spec.Type != "junit" && spec.Type != "provenance" {
		return fmt.Errorf("rule %s: unsupported evidence type %s", rule.ID, spec.Type)
	}
	if !evidenceDigest.MatchString(spec.SHA256) || !evidenceDigest.MatchString(spec.SubjectDigest) {
		return fmt.Errorf("rule %s: sha256 and subjectDigest must be exact SHA-256 digests", rule.ID)
	}
	if spec.MinimumItems < 0 || spec.MaximumFailures < 0 {
		return fmt.Errorf("rule %s: evidence thresholds must not be negative", rule.ID)
	}
	if spec.MaximumAge != "" {
		if duration, err := time.ParseDuration(spec.MaximumAge); err != nil || duration <= 0 {
			return fmt.Errorf("rule %s: maximumAge must be a positive duration", rule.ID)
		}
	}
	if strings.ContainsAny(spec.RequiredProducer, "\x00\r\n") {
		return fmt.Errorf("rule %s: requiredProducer is invalid", rule.ID)
	}
	return nil
}

func (ArtifactEvidence) Evaluate(_ context.Context, input sdk.EvalContext, rule sdk.Rule) ([]sdk.Finding, error) {
	var spec artifactEvidenceSpec
	if err := decodeSpec(rule, &spec); err != nil {
		return nil, err
	}
	files, err := input.Repository.Match(rule.Files, rule.Exclude)
	if err != nil {
		return nil, err
	}
	message := spec.Message
	if message == "" {
		message = "Pinned external evidence is missing, stale, unrelated, malformed, or outside threshold"
	}
	if len(files) == 0 {
		return []sdk.Finding{finding(rule, message+": artifact is missing", rule.Files[0], "missing", 1, 1)}, nil
	}
	if len(files) != 1 {
		return nil, fmt.Errorf("rule %s: artifact path matched %d files, expected one", rule.ID, len(files))
	}
	external := evidence.ExternalSpec{ID: rule.ID, Type: spec.Type, Path: files[0].Path, SHA256: spec.SHA256, SubjectDigest: spec.SubjectDigest, RequiredProducer: spec.RequiredProducer, MaximumAge: spec.MaximumAge, MinimumItems: spec.MinimumItems, MaximumFailures: spec.MaximumFailures}
	if _, err := evidence.InspectExternalBytes(external, files[0].Data, input.Now); err != nil {
		return []sdk.Finding{finding(rule, message+": "+err.Error(), files[0].Path, "verification", 1, 1)}, nil
	}
	return nil, nil
}
