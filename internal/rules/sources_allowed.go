package rules

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/openhoo/hoolicy/internal/document"
	"github.com/openhoo/hoolicy/sdk"
)

type SourcesAllowed struct{}

var imageDigestPattern = regexp.MustCompile(`@sha256:[0-9a-f]{64}$`)

type sourcesSpec struct {
	Registries    []string `yaml:"registries,omitempty"`
	NPM           []string `yaml:"npm,omitempty"`
	NuGet         []string `yaml:"nuget,omitempty"`
	RequireDigest bool     `yaml:"requireDigest,omitempty"`
	Message       string   `yaml:"message"`
}

func (SourcesAllowed) Validate(rule sdk.Rule) error {
	if err := requireFiles(rule); err != nil {
		return err
	}
	var spec sourcesSpec
	if err := decodeSpec(rule, &spec); err != nil {
		return err
	}
	if len(spec.Registries) == 0 && len(spec.NPM) == 0 && len(spec.NuGet) == 0 {
		return fmt.Errorf("rule %s: sources.allowed needs at least one allowlist", rule.ID)
	}
	for _, registry := range spec.Registries {
		if _, err := canonicalRegistry(registry); err != nil {
			return fmt.Errorf("rule %s: invalid registry %q: %w", rule.ID, registry, err)
		}
	}
	for _, allowlist := range []struct {
		name   string
		values []string
	}{{name: "npm", values: spec.NPM}, {name: "nuget", values: spec.NuGet}} {
		for _, value := range allowlist.values {
			if _, err := canonicalSourceURL(value); err != nil {
				return fmt.Errorf("rule %s: invalid %s source %q: %w", rule.ID, allowlist.name, value, err)
			}
		}
	}
	return nil
}

func (SourcesAllowed) Evaluate(_ context.Context, input sdk.EvalContext, rule sdk.Rule) ([]sdk.Finding, error) {
	var spec sourcesSpec
	if err := decodeSpec(rule, &spec); err != nil {
		return nil, err
	}
	files, err := input.Repository.Match(rule.Files, rule.Exclude)
	if err != nil {
		return nil, err
	}
	message := spec.Message
	if message == "" {
		message = "Artifact source is not allowed"
	}
	var findings []sdk.Finding
	for _, file := range files {
		name := strings.ToLower(filepath.Base(file.Path))
		extension := strings.ToLower(filepath.Ext(file.Path))
		switch {
		case name == ".npmrc":
			findings = append(findings, checkNPMSources(rule, file, spec, message)...)
		case name == "nuget.config" || strings.HasSuffix(name, ".nuget.config"):
			nugetFindings, parseErr := checkNuGetSources(rule, file, spec, message)
			if parseErr != nil {
				return nil, parseErr
			}
			findings = append(findings, nugetFindings...)
		case strings.HasPrefix(name, "dockerfile") || strings.HasPrefix(name, "containerfile"):
			findings = append(findings, checkDockerfileSources(rule, file, spec, message)...)
		case extension == ".yaml" || extension == ".yml" || extension == ".json":
			imageFindings, parseErr := checkStructuredImages(rule, file, spec, message)
			if parseErr != nil {
				return nil, parseErr
			}
			findings = append(findings, imageFindings...)
		}
	}
	return findings, nil
}

func checkNPMSources(rule sdk.Rule, file sdk.File, spec sourcesSpec, message string) []sdk.Finding {
	if len(spec.NPM) == 0 {
		return nil
	}
	var findings []sdk.Finding
	for index, data := range bytes.Split(file.Data, []byte{'\n'}) {
		line := index + 1
		text := strings.TrimSpace(string(data))
		key, value, found := strings.Cut(text, "=")
		key = strings.TrimSpace(key)
		if !found || (key != "registry" && !strings.HasSuffix(key, ":registry")) {
			continue
		}
		value = canonicalURL(value)
		if !containsCanonicalURL(spec.NPM, value) {
			findings = append(findings, finding(rule, fmt.Sprintf("%s: npm registry %s", message, redactURL(value)), file.Path, "npm:"+key, line, 1))
		}
	}
	return findings
}

func checkNuGetSources(rule sdk.Rule, file sdk.File, spec sourcesSpec, message string) ([]sdk.Finding, error) {
	if len(spec.NuGet) == 0 {
		return nil, nil
	}
	decoder := xml.NewDecoder(bytes.NewReader(file.Data))
	var findings []sdk.Finding
	inPackageSources := false
	for {
		token, err := decoder.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("%s: %w", file.Path, err)
		}
		if end, ok := token.(xml.EndElement); ok && strings.EqualFold(end.Name.Local, "packageSources") {
			inPackageSources = false
			continue
		}
		start, ok := token.(xml.StartElement)
		if !ok {
			continue
		}
		if strings.EqualFold(start.Name.Local, "packageSources") {
			inPackageSources = true
			continue
		}
		if !inPackageSources || !strings.EqualFold(start.Name.Local, "add") {
			continue
		}
		value := ""
		key := "source"
		for _, attribute := range start.Attr {
			if attribute.Name.Local == "value" {
				value = canonicalURL(attribute.Value)
			}
			if attribute.Name.Local == "key" {
				key = attribute.Value
			}
		}
		if value != "" && !containsCanonicalURL(spec.NuGet, value) {
			findings = append(findings, finding(rule, fmt.Sprintf("%s: NuGet source %s", message, redactURL(value)), file.Path, "nuget:"+key, 1, 1))
		}
	}
	return findings, nil
}

func checkDockerfileSources(rule sdk.Rule, file sdk.File, spec sourcesSpec, message string) []sdk.Finding {
	var findings []sdk.Finding
	logical := logicalLines(file.Data)
	stages := make(map[string]bool)
	for _, entry := range logical {
		fields := strings.Fields(entry.text)
		if len(fields) < 2 || !strings.EqualFold(fields[0], "FROM") {
			continue
		}
		image := fields[1]
		if strings.HasPrefix(image, "--platform=") && len(fields) > 2 {
			image = fields[2]
		}
		alias := ""
		for index := 2; index+1 < len(fields); index++ {
			if strings.EqualFold(fields[index], "AS") {
				alias = strings.ToLower(fields[index+1])
				break
			}
		}
		if !strings.ContainsAny(image, "${}") && !stages[strings.ToLower(image)] {
			if problem := imageProblem(image, spec); problem != "" {
				findings = append(findings, finding(rule, message+": "+problem, file.Path, "image:"+image, entry.line, 1))
			}
		}
		if alias != "" {
			stages[alias] = true
		}
	}
	return findings
}

func checkStructuredImages(rule sdk.Rule, file sdk.File, spec sourcesSpec, message string) ([]sdk.Finding, error) {
	documents, err := document.Parse(file, "auto")
	if err != nil {
		if json.Valid(file.Data) || strings.HasSuffix(file.Path, ".json") {
			return nil, err
		}
		return nil, err
	}
	var findings []sdk.Finding
	for _, item := range documents {
		walkImages(item.Data, "", func(key, image string) {
			if strings.ContainsAny(image, "${}") {
				return
			}
			if problem := imageProblem(image, spec); problem != "" {
				findings = append(findings, finding(rule, message+": "+problem, file.Path, "image:"+image, item.Line, item.Column))
			}
		})
	}
	return findings, nil
}

func walkImages(value any, parentKey string, visit func(key, image string)) {
	switch current := value.(type) {
	case map[string]any:
		for key, child := range current {
			lower := strings.ToLower(key)
			if text, ok := child.(string); ok && lower == "image" && structuredImageValue(text, parentKey, current) {
				visit(key, strings.TrimSpace(text))
			}
			if text, ok := child.(string); ok && lower == "repository" && imageConfiguration(parentKey, current) {
				image := strings.TrimSpace(text)
				if digest, ok := current["digest"].(string); ok && strings.TrimSpace(digest) != "" {
					image += "@" + strings.TrimPrefix(strings.TrimSpace(digest), "@")
				}
				visit(key, image)
			}
			walkImages(child, key, visit)
		}
	case []any:
		for _, child := range current {
			walkImages(child, parentKey, visit)
		}
	}
}

func structuredImageValue(value, parentKey string, object map[string]any) bool {
	value = strings.TrimSpace(value)
	if value == "" || strings.ContainsAny(value, " \t\r\n") || strings.HasPrefix(value, ".") || strings.HasPrefix(value, "/") {
		return false
	}
	if strings.Contains(value, "/") || strings.Contains(value, ":") || strings.Contains(value, "@") {
		return true
	}
	switch strings.ToLower(parentKey) {
	case "container", "containers", "initcontainer", "initcontainers":
		return true
	}
	for key := range object {
		switch strings.ToLower(key) {
		case "command", "entrypoint", "imagepullpolicy", "ports", "resources":
			return true
		}
	}
	return false
}

func imageConfiguration(parentKey string, object map[string]any) bool {
	if strings.EqualFold(parentKey, "image") {
		return true
	}
	for key := range object {
		switch strings.ToLower(key) {
		case "tag", "digest", "pullpolicy", "registry":
			return true
		}
	}
	return false
}

func imageProblem(image string, spec sourcesSpec) string {
	normalized := strings.TrimPrefix(strings.TrimSpace(image), "oci://")
	if normalized == "scratch" {
		return ""
	}
	registry := "docker.io"
	if slash := strings.IndexByte(normalized, '/'); slash >= 0 {
		first := normalized[:slash]
		if strings.ContainsAny(first, ".:") || first == "localhost" {
			registry = first
		}
	}
	if len(spec.Registries) > 0 && !containsRegistry(spec.Registries, registry) {
		return fmt.Sprintf("registry %s is not allowed", registry)
	}
	if strings.Contains(normalized, "@sha256:") && !imageDigestPattern.MatchString(normalized) {
		return fmt.Sprintf("image %s has an invalid sha256 digest", normalized)
	}
	if spec.RequireDigest && !imageDigestPattern.MatchString(normalized) {
		return fmt.Sprintf("image %s is not pinned by sha256 digest", normalized)
	}
	return ""
}

type logicalLine struct {
	line int
	text string
}

func logicalLines(data []byte) []logicalLine {
	var result []logicalLine
	current := ""
	start := 1
	for index, data := range bytes.Split(data, []byte{'\n'}) {
		line := index + 1
		text := strings.TrimSpace(string(data))
		if current == "" {
			start = line
		}
		if strings.HasPrefix(text, "#") {
			continue
		}
		continued := strings.HasSuffix(text, "\\")
		text = strings.TrimSpace(strings.TrimSuffix(text, "\\"))
		current = strings.TrimSpace(current + " " + text)
		if !continued && current != "" {
			result = append(result, logicalLine{line: start, text: current})
			current = ""
		}
	}
	return result
}

func canonicalURL(value string) string {
	canonical, err := canonicalSourceURL(value)
	if err != nil {
		return strings.TrimRight(strings.TrimSpace(value), "/")
	}
	return canonical
}

func containsCanonicalURL(values []string, expected string) bool {
	expected = canonicalURL(expected)
	for _, value := range values {
		if canonicalURL(value) == expected {
			return true
		}
	}
	return false
}

func containsRegistry(values []string, expected string) bool {
	for _, value := range values {
		canonical, err := canonicalRegistry(value)
		if err == nil && canonical == strings.ToLower(expected) {
			return true
		}
	}
	return false
}

func canonicalRegistry(value string) (string, error) {
	if value == "" || strings.TrimSpace(value) != value || strings.ContainsAny(value, "/@?# \t\r\n") {
		return "", errors.New("expected a registry host without scheme, path, or credentials")
	}
	parsed, err := url.Parse("https://" + value)
	if err != nil || parsed.Host == "" || parsed.Host != value || parsed.Hostname() == "" {
		return "", errors.New("expected a valid registry host")
	}
	return strings.ToLower(value), nil
}

func canonicalSourceURL(value string) (string, error) {
	if value == "" || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\r\n") {
		return "", errors.New("expected an absolute HTTP(S) URL")
	}
	parsed, err := url.Parse(value)
	if err != nil || (!strings.EqualFold(parsed.Scheme, "http") && !strings.EqualFold(parsed.Scheme, "https")) || parsed.Host == "" {
		return "", errors.New("expected an absolute HTTP(S) URL")
	}
	if parsed.User != nil {
		return "", errors.New("embedded credentials are forbidden")
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("query strings and fragments are forbidden")
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	parsed.Host = strings.ToLower(parsed.Host)
	parsed.Path = strings.TrimRight(parsed.Path, "/")
	return parsed.String(), nil
}

func redactURL(value string) string {
	parsed, err := url.Parse(value)
	if err != nil {
		return "<invalid-url>"
	}
	parsed.User = nil
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String()
}
