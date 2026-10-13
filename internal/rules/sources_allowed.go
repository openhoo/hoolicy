package rules

import (
	"bytes"
	"context"
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
	"go.yaml.in/yaml/v3"
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
			imageFindings, parseErr := checkStructuredImages(rule, file, spec, message, input.Metrics)
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
	depth, packageSourcesDepth := 0, 0
	rootSeen := false
	for {
		token, err := decoder.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				if !rootSeen {
					return nil, fmt.Errorf("%s: XML document requires a root element", file.Path)
				}
				break
			}
			return nil, fmt.Errorf("%s: %w", file.Path, err)
		}
		if _, ok := token.(xml.EndElement); ok {
			if depth == packageSourcesDepth {
				packageSourcesDepth = 0
			}
			depth--
			continue
		}
		if text, ok := token.(xml.CharData); ok && depth == 0 && strings.TrimSpace(string(text)) != "" {
			return nil, fmt.Errorf("%s: XML content outside the root element", file.Path)
		}
		start, ok := token.(xml.StartElement)
		if !ok {
			continue
		}
		if depth == 0 {
			if rootSeen {
				return nil, fmt.Errorf("%s: trailing XML root element", file.Path)
			}
			rootSeen = true
		}
		depth++
		if err := document.ValidateXMLAttributes(start); err != nil {
			return nil, fmt.Errorf("%s: %w", file.Path, err)
		}
		if strings.EqualFold(start.Name.Local, "packageSources") {
			if packageSourcesDepth == 0 {
				packageSourcesDepth = depth
			}
			continue
		}
		if packageSourcesDepth == 0 || !strings.EqualFold(start.Name.Local, "add") {
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

func checkStructuredImages(rule sdk.Rule, file sdk.File, spec sourcesSpec, message string, metrics *sdk.EvaluationMetrics) ([]sdk.Finding, error) {
	var findings []sdk.Finding
	visit := func(line, column int) func(string, string) {
		return func(_ string, image string) {
			if strings.ContainsAny(image, "${}") {
				return
			}
			if problem := imageProblem(image, spec); problem != "" {
				findings = append(findings, finding(rule, message+": "+problem, file.Path, "image:"+image, line, column))
			}
		}
	}
	if extension := strings.ToLower(filepath.Ext(file.Path)); extension == ".yaml" || extension == ".yml" {
		// Scanned YAML belongs to foreign tools. Some, such as GitLab CI,
		// accept repeated mapping keys, so inspect the syntax tree and visit
		// every occurrence rather than rejecting or silently collapsing it.
		documents, hit, err := document.ParseCachedYAMLNodes(file)
		if err != nil {
			return nil, err
		}
		if hit && metrics != nil {
			metrics.ParseCacheHits++
		}
		for _, item := range documents {
			walker := yamlImageWalker{visited: map[yamlWalkKey]bool{}}
			if err := walker.walk(item.Node, "", visit(item.Line, item.Column)); err != nil {
				return nil, fmt.Errorf("%s: %w", file.Path, err)
			}
		}
		return findings, nil
	}
	documents, hit, err := document.ParseCached(file, "auto")
	if err != nil {
		return nil, err
	}
	if hit && metrics != nil {
		metrics.ParseCacheHits++
	}
	for _, item := range documents {
		walkImages(item.Data, "", visit(item.Line, item.Column))
	}
	return findings, nil
}

// yamlWalkLimit bounds node visits so alias and merge graphs cannot expand
// exponentially; normal documents stay far below it.
const yamlWalkLimit = 1_000_000

type yamlWalkKey struct {
	node      *yaml.Node
	parentKey string
}

type yamlImageWalker struct {
	visited map[yamlWalkKey]bool
	steps   int
}

type yamlPair struct {
	key   string
	value *yaml.Node
}

// walk mirrors walkImages for a YAML syntax tree. Duplicate keys are all
// visited; sibling lookups use the last occurrence like common forge
// parsers. Merge keys and aliases are resolved, and each node is processed
// at most once per parent key.
func (w *yamlImageWalker) walk(node *yaml.Node, parentKey string, visit func(key, image string)) error {
	node = resolveYAMLAlias(node)
	if node == nil {
		return nil
	}
	walkKey := yamlWalkKey{node: node, parentKey: parentKey}
	if w.visited[walkKey] {
		return nil
	}
	w.visited[walkKey] = true
	w.steps++
	if w.steps > yamlWalkLimit {
		return fmt.Errorf("YAML alias expansion exceeds %d nodes", yamlWalkLimit)
	}
	switch node.Kind {
	case yaml.MappingNode:
		pairs, err := w.mappingPairs(node, 0)
		if err != nil {
			return err
		}
		object := make(map[string]any, len(pairs))
		for _, pair := range pairs {
			object[pair.key] = yamlScalarValue(pair.value)
		}
		for _, pair := range pairs {
			lower := strings.ToLower(pair.key)
			if text, ok := yamlScalarValue(pair.value).(string); ok {
				if lower == "image" && structuredImageValue(text, parentKey, object) {
					visit(pair.key, strings.TrimSpace(text))
				}
				if lower == "repository" && imageConfiguration(parentKey, object) {
					image := strings.TrimSpace(text)
					if digest, ok := object["digest"].(string); ok && strings.TrimSpace(digest) != "" {
						image += "@" + strings.TrimPrefix(strings.TrimSpace(digest), "@")
					}
					visit(pair.key, image)
				}
			}
			if err := w.walk(pair.value, pair.key, visit); err != nil {
				return err
			}
		}
	case yaml.SequenceNode:
		for _, child := range node.Content {
			if err := w.walk(child, parentKey, visit); err != nil {
				return err
			}
		}
	}
	return nil
}

// mappingPairs returns the effective pairs of a mapping: inherited merge-key
// pairs not overridden by an explicit key (earlier merge sources win), then
// every explicit pair in document order, including repeated keys.
func (w *yamlImageWalker) mappingPairs(node *yaml.Node, depth int) ([]yamlPair, error) {
	if depth > 64 {
		return nil, errors.New("YAML merge nesting is too deep")
	}
	var merged, own []yamlPair
	for index := 0; index+1 < len(node.Content); index += 2 {
		key, value := node.Content[index], node.Content[index+1]
		w.steps++
		if w.steps > yamlWalkLimit {
			return nil, fmt.Errorf("YAML alias expansion exceeds %d nodes", yamlWalkLimit)
		}
		if key.Kind == yaml.ScalarNode && key.Value == "<<" && key.ShortTag() == "!!merge" {
			sources := []*yaml.Node{value}
			if resolved := resolveYAMLAlias(value); resolved != nil && resolved.Kind == yaml.SequenceNode {
				sources = resolved.Content
			}
			for position := range sources {
				source := resolveYAMLAlias(sources[position])
				if source == nil || source.Kind != yaml.MappingNode {
					continue
				}
				pairs, err := w.mappingPairs(source, depth+1)
				if err != nil {
					return nil, err
				}
				merged = append(merged, pairs...)
			}
			continue
		}
		name, ok := yamlScalarValue(key).(string)
		if !ok {
			if decoded := yamlScalarValue(key); decoded != nil {
				name = fmt.Sprint(decoded)
			} else {
				name = key.Value
			}
		}
		own = append(own, yamlPair{key: name, value: value})
	}
	explicit := make(map[string]bool, len(own))
	for _, pair := range own {
		explicit[pair.key] = true
	}
	effective := make([]yamlPair, 0, len(merged)+len(own))
	inherited := make(map[string]bool, len(merged))
	for _, pair := range merged {
		if explicit[pair.key] || inherited[pair.key] {
			continue
		}
		inherited[pair.key] = true
		effective = append(effective, pair)
	}
	return append(effective, own...), nil
}

func resolveYAMLAlias(node *yaml.Node) *yaml.Node {
	for depth := 0; node != nil && node.Kind == yaml.AliasNode; depth++ {
		if depth > 64 {
			return nil
		}
		node = node.Alias
	}
	return node
}

// yamlScalarValue decodes a scalar like the value decoder would, including
// custom forge tags such as !reference, and returns nil for collections.
func yamlScalarValue(node *yaml.Node) any {
	node = resolveYAMLAlias(node)
	if node == nil || node.Kind != yaml.ScalarNode {
		return nil
	}
	var value any
	if err := node.Decode(&value); err != nil {
		return node.Value
	}
	return value
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
