package sdk

import (
	"strings"
	"testing"
)

func TestExplanationIsAuthoritativeIndependentAndDigestBound(t *testing.T) {
	t.Parallel()
	rule := Rule{ID: "demo.rule", Description: "Check reviewed inputs", Rationale: "Avoid drift", Explanation: &Explanation{Expectation: "Reviewed inputs", Steps: []string{"Review the inputs"}, References: []Reference{{Title: "Guide", URL: "https://example.invalid/guide"}}}}
	item := Finding{Message: "Missing input", Policy: &PolicyContext{Description: "Spoofed guidance"}}
	item.Finalize(rule)
	if item.Policy.Description != rule.Description || item.Policy.Rationale != rule.Rationale || item.Policy.Explanation.Expectation != rule.Explanation.Expectation {
		t.Fatalf("guidance was not bound to the configured policy: %+v", item.Policy)
	}
	fingerprint, findingDigest, policyDigest := item.Fingerprint, item.FindingDigest, item.PolicyDigest
	item.Policy.Explanation.Steps[0] = "Spoofed step"
	item.Policy.Explanation.References[0].Title = "Spoofed reference"
	if rule.Explanation.Steps[0] != "Review the inputs" || rule.Explanation.References[0].Title != "Guide" {
		t.Fatal("finding guidance aliases configured slices")
	}
	rule.Explanation.Impact = "Installation becomes unreproducible"
	item.Finalize(rule)
	if item.PolicyDigest == policyDigest || item.Fingerprint != fingerprint || item.FindingDigest != findingDigest {
		t.Fatal("explanation must change policy identity while retaining finding identity")
	}
	rule.Explanation = nil
	item.Finalize(rule)
	if item.Policy.Explanation != nil {
		t.Fatal("finalization retained implementation-authored explanation")
	}
}

func TestExplanationRejectsUnsafeReferencesAndExcessiveGuidance(t *testing.T) {
	t.Parallel()
	for _, url := range []string{"http://example.invalid", "javascript:alert(1)", "/guide", "https://", "https://user:secret@example.invalid/guide", "https://example.invalid/guide?token=secret", "https://example.invalid/guide?", "https://example.invalid/guide\n", "https://example.invalid/\u202ehidden"} {
		explanation := &Explanation{References: []Reference{{Title: "Guide", URL: url}}}
		if err := explanation.Validate(); err == nil {
			t.Errorf("unsafe reference admitted: %q", url)
		} else if strings.Contains(err.Error(), "secret") {
			t.Fatal("validation echoed a credential-bearing reference")
		}
	}
	for _, explanation := range []*Explanation{{}, {Expectation: " "}, {Impact: strings.Repeat("x", 4097)}, {Steps: []string{""}}, {Steps: make([]string, 17)}, {References: make([]Reference, 9)}, {References: []Reference{{URL: "https://example.invalid"}}}} {
		if err := explanation.Validate(); err == nil {
			t.Errorf("invalid guidance admitted: %+v", explanation)
		}
	}
	for _, explanation := range []*Explanation{nil, {Expectation: "Reviewed inputs"}, {References: []Reference{{Title: "Guide", URL: "https://example.invalid/guide#review"}}}} {
		if err := explanation.Validate(); err != nil {
			t.Errorf("valid guidance rejected: %v", err)
		}
	}
}
