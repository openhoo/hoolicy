package policylint

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/openhoo/hoolicy/internal/config"
	"github.com/openhoo/hoolicy/sdk"
	"go.yaml.in/yaml/v3"
)

type Finding struct {
	Check       string `json:"check"`
	Scope       string `json:"scope"`
	Message     string `json:"message"`
	Heuristic   string `json:"heuristic"`
	Remediation string `json:"remediation"`
}

func Pack(pack *config.Pack, previous *config.Pack, disabled []string) []Finding {
	disable := make(map[string]bool, len(disabled))
	for _, item := range disabled {
		disable[item] = true
	}
	var findings []Finding
	add := func(finding Finding) {
		key := finding.Check + ":" + finding.Scope
		if !disable[key] {
			findings = append(findings, finding)
		}
	}
	serialized, _ := yaml.Marshal(pack.Rules)
	for name := range pack.Parameters {
		if !strings.Contains(string(serialized), "{{ "+name+" }}") && !strings.Contains(string(serialized), "{{"+name+"}}") {
			add(Finding{Check: "unused-parameter", Scope: "parameter:" + name, Message: "parameter is declared but unused", Heuristic: "No exact typed parameter placeholder appears in any rule.", Remediation: "Remove the parameter or reference it as {{ " + name + " }}."})
		}
	}
	redundant := make(map[string]string)
	for _, rule := range pack.Rules {
		if len(strings.TrimSpace(rule.Remediation)) < 20 {
			add(Finding{Check: "weak-remediation", Scope: rule.ID, Message: "remediation is too short to guide ownership and outcome", Heuristic: "Remediation text contains fewer than 20 non-whitespace characters.", Remediation: "State the concrete safe outcome and responsible action."})
		}
		for _, pattern := range rule.Files {
			clean := strings.TrimSpace(pattern)
			if clean == "*" || clean == "**" || clean == "**/*" || clean == "**/**" {
				add(Finding{Check: "overbroad-scope", Scope: rule.ID, Message: "rule targets nearly every repository file", Heuristic: "A global glob increases parser errors and false-positive pressure.", Remediation: "Use explicit formats or owned directories; retain global scope only with measured fixtures."})
				break
			}
		}
		if rule.Kind == "text" && structuredScope(rule.Files) {
			add(Finding{Check: "structured-as-text", Scope: rule.ID, Message: "text rule targets structured documents", Heuristic: "JSON, YAML, TOML, XML, INI, or dotenv content has a supported parser and should not rely on layout regexes.", Remediation: "Use structured.cel or a dedicated structured rule kind."})
		}
		key := semanticRuleKey(rule)
		if owner := redundant[key]; owner != "" {
			add(Finding{Check: "redundant-rule", Scope: rule.ID, Message: "rule behavior duplicates " + owner, Heuristic: "Kind, file scope, exclusions, and spec are identical.", Remediation: "Merge ownership and control mappings into one rule."})
		} else {
			redundant[key] = rule.ID
		}
	}
	if previous != nil {
		old := make(map[string]sdk.Rule, len(previous.Rules))
		for _, rule := range previous.Rules {
			old[rule.ID] = rule
		}
		for _, rule := range pack.Rules {
			if prior, exists := old[rule.ID]; exists && rule.Severity.Rank() > prior.Severity.Rank() {
				add(Finding{Check: "severity-increase", Scope: rule.ID, Message: fmt.Sprintf("severity increased from %s to %s", prior.Severity, rule.Severity), Heuristic: "A higher severity can newly block consuming repositories.", Remediation: "Document impact, measure false positives, and release as an explicit compatibility change."})
			}
		}
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Check != findings[j].Check {
			return findings[i].Check < findings[j].Check
		}
		return findings[i].Scope < findings[j].Scope
	})
	return findings
}

func structuredScope(patterns []string) bool {
	for _, pattern := range patterns {
		lower := strings.ToLower(pattern)
		for _, marker := range []string{".json", ".yaml", ".yml", ".toml", ".xml", ".ini", ".env"} {
			if strings.Contains(lower, marker) {
				return true
			}
		}
	}
	return false
}

func semanticRuleKey(rule sdk.Rule) string {
	data, _ := json.Marshal(struct {
		Kind           string
		Files, Exclude []string
		Spec           map[string]any
	}{rule.Kind, rule.Files, rule.Exclude, rule.Spec})
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}
