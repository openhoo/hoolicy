package rules

import (
	"context"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"

	"github.com/openhoo/hoolicy/internal/document"
	"github.com/openhoo/hoolicy/sdk"
)

type DeploymentInvariants struct{}

type deploymentSpec struct {
	Platform               string   `yaml:"platform"`
	RequireImmutableImages bool     `yaml:"requireImmutableImages,omitempty"`
	RequireResourceLimits  bool     `yaml:"requireResourceLimits,omitempty"`
	RequireNonRoot         bool     `yaml:"requireNonRoot,omitempty"`
	AllowTemplatedImages   bool     `yaml:"allowTemplatedImages,omitempty"`
	ApprovedRegistries     []string `yaml:"approvedRegistries,omitempty"`
	Message                string   `yaml:"message,omitempty"`
}

func (DeploymentInvariants) Validate(rule sdk.Rule) error {
	if err := requireFiles(rule); err != nil {
		return err
	}
	var spec deploymentSpec
	if err := decodeSpec(rule, &spec); err != nil {
		return err
	}
	if spec.Platform != "kubernetes" && spec.Platform != "compose" && spec.Platform != "terraform-plan" {
		return fmt.Errorf("rule %s: platform must be kubernetes, compose, or terraform-plan", rule.ID)
	}
	for _, registry := range spec.ApprovedRegistries {
		if _, err := canonicalRegistry(registry); err != nil {
			return fmt.Errorf("rule %s: approved registry %s: %w", rule.ID, registry, err)
		}
	}
	return nil
}

func (DeploymentInvariants) Evaluate(_ context.Context, input sdk.EvalContext, rule sdk.Rule) ([]sdk.Finding, error) {
	var spec deploymentSpec
	if err := decodeSpec(rule, &spec); err != nil {
		return nil, err
	}
	files, err := input.Repository.Match(rule.Files, rule.Exclude)
	if err != nil {
		return nil, err
	}
	message := spec.Message
	if message == "" {
		message = "Deployment violates reviewed image, resource, or security invariants"
	}
	var findings []sdk.Finding
	for _, file := range files {
		format := "yaml"
		if spec.Platform == "terraform-plan" {
			format = "json"
		}
		documents, hit, err := document.ParseCached(file, format)
		if err != nil {
			return nil, err
		}
		if hit && input.Metrics != nil {
			input.Metrics.ParseCacheHits++
		}
		for _, item := range documents {
			root, ok := item.Data.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("%s: deployment document must be an object", file.Path)
			}
			switch spec.Platform {
			case "kubernetes":
				findings = append(findings, inspectKubernetesDeployment(rule, file.Path, root, spec, message)...)
			case "compose":
				findings = append(findings, inspectComposeDeployment(rule, file.Path, root, spec, message)...)
			case "terraform-plan":
				findings = append(findings, inspectTerraformPlan(rule, file.Path, root, spec, message)...)
			}
		}
	}
	return findings, nil
}

func inspectKubernetesDeployment(rule sdk.Rule, path string, root map[string]any, spec deploymentSpec, message string) []sdk.Finding {
	kind, _ := root["kind"].(string)
	var pod map[string]any
	switch kind {
	case "Pod":
		pod, _ = root["spec"].(map[string]any)
	case "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job":
		pod = nestedMap(root, "spec", "template", "spec")
	case "CronJob":
		pod = nestedMap(root, "spec", "jobTemplate", "spec", "template", "spec")
	default:
		return nil
	}
	if pod == nil {
		return []sdk.Finding{finding(rule, message+": "+kind+" pod spec is missing", path, "pod-spec:missing", 1, 1)}
	}
	podSecurity, _ := pod["securityContext"].(map[string]any)
	podNonRoot, _ := podSecurity["runAsNonRoot"].(bool)
	var findings []sdk.Finding
	for _, group := range []string{"initContainers", "containers"} {
		containers, _ := pod[group].([]any)
		for index, raw := range containers {
			container, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			name, _ := container["name"].(string)
			if name == "" {
				name = fmt.Sprintf("%s-%d", group, index)
			}
			key := group + ":" + name
			if image, _ := container["image"].(string); image != "" {
				if problem := deploymentImageProblem(image, spec); problem != "" {
					findings = append(findings, finding(rule, message+": "+problem, path, key+":image", 1, 1))
				}
			} else {
				findings = append(findings, finding(rule, message+": container image is missing", path, key+":image", 1, 1))
			}
			if spec.RequireResourceLimits {
				limits := nestedMap(container, "resources", "limits")
				if !positiveResourceLimit(limits["cpu"], kubernetesResourceQuantity) || !positiveResourceLimit(limits["memory"], kubernetesResourceQuantity) {
					findings = append(findings, finding(rule, message+": container "+name+" needs CPU and memory limits", path, key+":limits", 1, 1))
				}
			}
			if spec.RequireNonRoot {
				security, _ := container["securityContext"].(map[string]any)
				nonRoot := podNonRoot
				if value, exists := security["runAsNonRoot"]; exists {
					nonRoot, _ = value.(bool)
				}
				if !nonRoot {
					findings = append(findings, finding(rule, message+": container "+name+" must set runAsNonRoot", path, key+":non-root", 1, 1))
				}
			}
		}
	}
	return findings
}

func inspectComposeDeployment(rule sdk.Rule, path string, root map[string]any, spec deploymentSpec, message string) []sdk.Finding {
	services, ok := root["services"].(map[string]any)
	if !ok {
		return nil
	}
	var findings []sdk.Finding
	for name, raw := range services {
		service, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		image, _ := service["image"].(string)
		buildService := false
		switch build := service["build"].(type) {
		case string:
			buildService = strings.TrimSpace(build) != ""
		case map[string]any:
			buildService = true
		}
		if image == "" && !buildService {
			continue
		}
		if image == "" {
			if spec.RequireImmutableImages || len(spec.ApprovedRegistries) > 0 {
				findings = append(findings, finding(rule, message+": service "+name+" image is unverifiable because it is built locally", path, "service:"+name+":image", 1, 1))
			}
		} else if problem := deploymentImageProblem(image, spec); problem != "" {
			findings = append(findings, finding(rule, message+": "+problem, path, "service:"+name+":image", 1, 1))
		}
		if spec.RequireResourceLimits {
			limits := nestedMap(service, "deploy", "resources", "limits")
			cpu, hasCPU := limits["cpus"]
			if !hasCPU {
				cpu = service["cpus"]
			}
			memory, hasMemory := limits["memory"]
			if !hasMemory {
				memory = service["mem_limit"]
			}
			if !positiveResourceLimit(cpu, composeCPUQuantity) || !positiveComposeMemoryLimit(memory) {
				findings = append(findings, finding(rule, message+": service "+name+" needs CPU and memory limits", path, "service:"+name+":limits", 1, 1))
			}
		}
		if spec.RequireNonRoot {
			user := stringValue(service["user"], "")
			readOnly, _ := service["read_only"].(bool)
			if !explicitNonRootUser(user) || !readOnly {
				findings = append(findings, finding(rule, message+": service "+name+" needs a non-root user and read_only filesystem", path, "service:"+name+":security", 1, 1))
			}
		}
	}
	return findings
}

func inspectTerraformPlan(rule sdk.Rule, path string, root map[string]any, spec deploymentSpec, message string) []sdk.Finding {
	if _, ok := root["format_version"].(string); !ok {
		return []sdk.Finding{finding(rule, message+": Terraform plan format_version is missing", path, "format:missing", 1, 1)}
	}
	var findings []sdk.Finding
	changes, _ := root["resource_changes"].([]any)
	for index, raw := range changes {
		change, _ := raw.(map[string]any)
		address := stringValue(change["address"], fmt.Sprintf("resource-%d", index))
		after := nestedMap(change, "change", "after")
		walkDeploymentImages(after, func(key, image string) {
			if problem := deploymentImageProblem(image, spec); problem != "" {
				findings = append(findings, finding(rule, message+": "+problem, path, "resource:"+address+":"+key, 1, 1))
			}
		})
	}
	return findings
}

func deploymentImageProblem(image string, spec deploymentSpec) string {
	if spec.AllowTemplatedImages && isTemplateExpression(image) {
		return ""
	}
	return imageProblem(image, sourcesSpec{Registries: spec.ApprovedRegistries, RequireDigest: spec.RequireImmutableImages})
}

func isTemplateExpression(value string) bool {
	return strings.Contains(value, "${") && strings.Contains(value, "}") || strings.Contains(value, "{{") && strings.Contains(value, "}}")
}

var (
	// Kubernetes uses case-sensitive SI/binary suffixes or a decimal exponent.
	kubernetesResourceQuantity = regexp.MustCompile(`^\+?([0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[numkMGTPE]|[KMGTPE]i|[eE]([+-]?[0-9]+))?$`)
	composeCPUQuantity         = regexp.MustCompile(`^\+?([0-9]+(?:\.[0-9]*)?(?:[eE][+-]?[0-9]+)?|\.[0-9]+(?:[eE][+-]?[0-9]+)?)$`)
	// Docker byte quantities permit case-insensitive k/m/g/t/p units and b/ib.
	composeMemoryQuantity = regexp.MustCompile(`(?i)^\+?([0-9]+(?:\.[0-9]*)?(?:e[+-]?[0-9]+)?|\.[0-9]+(?:e[+-]?[0-9]+)?)(?: ?(b|[kmgtp](?:b|ib)?))?$`)
)

func positiveResourceLimit(value any, syntax *regexp.Regexp) bool {
	switch number := value.(type) {
	case int:
		return number > 0
	case int64:
		return number > 0
	case uint64:
		return number > 0
	case float64:
		return number > 0 && !math.IsInf(number, 0)
	}
	text := strings.TrimSpace(stringValue(value, ""))
	if text == "" {
		return false
	}
	parts := syntax.FindStringSubmatch(text)
	if parts == nil {
		return false
	}
	if syntax == kubernetesResourceQuantity && parts[2] != "" {
		if _, err := strconv.ParseInt(parts[2], 10, 64); err != nil {
			return false
		}
	}
	parsed, err := strconv.ParseFloat(parts[1], 64)
	return err == nil && parsed > 0 && !math.IsInf(parsed, 0)
}

func positiveComposeMemoryLimit(value any) bool {
	if !positiveResourceLimit(value, composeMemoryQuantity) {
		return false
	}
	var bytes float64
	switch number := value.(type) {
	case int:
		return number > 0
	case int64:
		return number > 0
	case uint64:
		return number > 0 && number < 1<<63
	case float64:
		bytes = number
	default:
		parts := composeMemoryQuantity.FindStringSubmatch(strings.TrimSpace(stringValue(value, "")))
		bytes, _ = strconv.ParseFloat(parts[1], 64)
		if suffix := strings.ToLower(parts[2]); suffix != "" && suffix != "b" {
			power := strings.IndexByte("kmgtp", suffix[0]) + 1
			bytes *= math.Pow(1024, float64(power))
		}
	}
	// Compose converts byte quantities to int64; fractions below one byte
	// become zero, and zero disables the memory limit.
	return bytes >= 1 && bytes < float64(1<<63)
}

func explicitNonRootUser(value string) bool {
	principal := strings.TrimSpace(strings.SplitN(value, ":", 2)[0])
	if principal == "" || strings.EqualFold(principal, "root") || strings.ContainsAny(principal, "${}") {
		return false
	}
	if numeric, err := strconv.ParseUint(principal, 10, 32); err == nil {
		return numeric > 0
	}
	return true
}

func nestedMap(root map[string]any, keys ...string) map[string]any {
	current := root
	for _, key := range keys {
		next, ok := current[key].(map[string]any)
		if !ok {
			return nil
		}
		current = next
	}
	return current
}
func walkDeploymentImages(value any, visit func(string, string)) {
	var walk func(any, string)
	walk = func(current any, key string) {
		switch item := current.(type) {
		case map[string]any:
			for childKey, child := range item {
				if text, ok := child.(string); ok && (childKey == "image" || childKey == "image_id" || childKey == "container_image") {
					visit(key+childKey, text)
				} else {
					walk(child, key+childKey+".")
				}
			}
		case []any:
			for index, child := range item {
				walk(child, fmt.Sprintf("%s%d.", key, index))
			}
		}
	}
	walk(value, "")
}
