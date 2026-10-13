package sdk

import (
	"encoding/json"
	"math"
	"testing"
)

func TestDigestsDoNotIdentifyUnencodableMetadata(t *testing.T) {
	cycle := map[string]any{}
	cycle["self"] = cycle
	for name, value := range map[string]any{
		"channel": make(chan int), "NaN": math.NaN(), "infinity": math.Inf(1),
		"cycle": cycle, "invalid raw JSON": json.RawMessage("{"),
	} {
		t.Run(name, func(t *testing.T) {
			rule := Rule{ID: "demo.rule", Severity: SeverityError, Spec: map[string]any{"value": value}}
			if digest := RuleDigest(rule); digest != "" {
				t.Fatalf("encoding failure acquired a valid rule digest: %s", digest)
			}
			finding := Finding{Properties: map[string]any{"value": value}}
			if err := finding.Validate(); err == nil {
				t.Fatal("unencodable finding metadata accepted")
			}
			finding.Finalize(Rule{ID: "demo.rule", Severity: SeverityError})
			if finding.FindingDigest != "" {
				t.Fatalf("encoding failure acquired a valid finding digest: %s", finding.FindingDigest)
			}
		})
	}
}
