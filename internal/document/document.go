package document

import (
	"bufio"
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/openhoo/hoolicy/sdk"
	"go.yaml.in/yaml/v3"
)

type Document struct {
	Path   string
	Index  int
	Line   int
	Column int
	Data   any
	Node   *yaml.Node
}

func Parse(file sdk.File, format string) ([]Document, error) {
	if format == "" || format == "auto" {
		format = detect(file.Path)
	}
	switch strings.ToLower(format) {
	case "json":
		return parseJSON(file)
	case "yaml", "yml":
		return parseYAML(file)
	case "toml":
		return parseTOML(file)
	case "xml":
		return parseXML(file)
	case "dotenv", "ini", "npmrc":
		return parseKeyValues(file)
	default:
		return nil, fmt.Errorf("%s: unsupported document format %q", file.Path, format)
	}
}

func detect(path string) string {
	name := strings.ToLower(filepath.Base(path))
	switch {
	case name == ".npmrc" || strings.HasSuffix(name, ".ini") || strings.HasSuffix(name, ".config"):
		return "ini"
	case strings.HasPrefix(name, ".env"):
		return "dotenv"
	}
	switch strings.ToLower(filepath.Ext(name)) {
	case ".json":
		return "json"
	case ".yaml", ".yml":
		return "yaml"
	case ".toml":
		return "toml"
	case ".xml", ".csproj", ".props":
		return "xml"
	default:
		return ""
	}
}

func parseJSON(file sdk.File) ([]Document, error) {
	decoder := json.NewDecoder(bytes.NewReader(file.Data))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, fmt.Errorf("%s: %w", file.Path, err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("%s: trailing JSON value", file.Path)
		}
		return nil, fmt.Errorf("%s: %w", file.Path, err)
	}
	return []Document{{Path: file.Path, Line: 1, Column: 1, Data: normalize(value)}}, nil
}

func parseYAML(file sdk.File) ([]Document, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(file.Data))
	var documents []Document
	for index := 0; ; index++ {
		var node yaml.Node
		err := decoder.Decode(&node)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%s: %w", file.Path, err)
		}
		if len(node.Content) == 0 {
			continue
		}
		if err := uniqueKeys(&node); err != nil {
			return nil, fmt.Errorf("%s: %w", file.Path, err)
		}
		var value any
		if err := node.Decode(&value); err != nil {
			return nil, fmt.Errorf("%s: %w", file.Path, err)
		}
		content := node.Content[0]
		documents = append(documents, Document{
			Path: file.Path, Index: index, Line: content.Line, Column: content.Column,
			Data: normalize(value), Node: content,
		})
	}
	return documents, nil
}

func parseTOML(file sdk.File) ([]Document, error) {
	value := make(map[string]any)
	if _, err := toml.Decode(string(file.Data), &value); err != nil {
		return nil, fmt.Errorf("%s: %w", file.Path, err)
	}
	return []Document{{Path: file.Path, Line: 1, Column: 1, Data: normalize(value)}}, nil
}

type xmlNode struct {
	XMLName xml.Name
	Attrs   []xml.Attr `xml:",any,attr"`
	Text    string     `xml:",chardata"`
	Nodes   []xmlNode  `xml:",any"`
}

func parseXML(file sdk.File) ([]Document, error) {
	var root xmlNode
	decoder := xml.NewDecoder(bytes.NewReader(file.Data))
	if err := decoder.Decode(&root); err != nil {
		return nil, fmt.Errorf("%s: %w", file.Path, err)
	}
	return []Document{{Path: file.Path, Line: 1, Column: 1, Data: xmlValue(root)}}, nil
}

func xmlValue(node xmlNode) map[string]any {
	value := map[string]any{"name": node.XMLName.Local}
	if text := strings.TrimSpace(node.Text); text != "" {
		value["text"] = text
	}
	if len(node.Attrs) > 0 {
		attributes := make(map[string]any, len(node.Attrs))
		for _, attribute := range node.Attrs {
			attributes[attribute.Name.Local] = attribute.Value
		}
		value["attributes"] = attributes
	}
	if len(node.Nodes) > 0 {
		children := make([]any, 0, len(node.Nodes))
		for _, child := range node.Nodes {
			children = append(children, xmlValue(child))
		}
		value["children"] = children
	}
	return value
}

func parseKeyValues(file sdk.File) ([]Document, error) {
	result := make(map[string]any)
	section := ""
	scanner := bufio.NewScanner(bytes.NewReader(file.Data))
	for line := 1; scanner.Scan(); line++ {
		text := strings.TrimSpace(scanner.Text())
		if text == "" || strings.HasPrefix(text, "#") || strings.HasPrefix(text, ";") {
			continue
		}
		if strings.HasPrefix(text, "[") && strings.HasSuffix(text, "]") {
			section = strings.TrimSpace(text[1 : len(text)-1])
			continue
		}
		key, value, found := strings.Cut(text, "=")
		if !found {
			return nil, fmt.Errorf("%s:%d: expected key=value", file.Path, line)
		}
		key = strings.TrimSpace(key)
		if section != "" {
			key = section + "." + key
		}
		value = strings.TrimSpace(value)
		if existing, exists := result[key]; exists {
			switch values := existing.(type) {
			case []any:
				result[key] = append(values, value)
			default:
				result[key] = []any{existing, value}
			}
		} else {
			result[key] = value
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("%s: %w", file.Path, err)
	}
	return []Document{{Path: file.Path, Line: 1, Column: 1, Data: result}}, nil
}

func normalize(value any) any {
	switch current := value.(type) {
	case map[string]any:
		result := make(map[string]any, len(current))
		for key, entry := range current {
			result[key] = normalize(entry)
		}
		return result
	case map[any]any:
		result := make(map[string]any, len(current))
		for key, entry := range current {
			result[fmt.Sprint(key)] = normalize(entry)
		}
		return result
	case []any:
		result := make([]any, len(current))
		for i, entry := range current {
			result[i] = normalize(entry)
		}
		return result
	case json.Number:
		if integer, err := strconv.ParseInt(string(current), 10, 64); err == nil {
			return integer
		}
		if number, err := strconv.ParseFloat(string(current), 64); err == nil {
			return number
		}
		return string(current)
	default:
		return current
	}
}

func uniqueKeys(node *yaml.Node) error {
	if node.Kind == yaml.MappingNode {
		seen := map[string]*yaml.Node{}
		for i := 0; i+1 < len(node.Content); i += 2 {
			key := node.Content[i]
			if previous, exists := seen[key.Value]; exists {
				return fmt.Errorf("duplicate key %q at %d:%d (first at %d:%d)", key.Value, key.Line, key.Column, previous.Line, previous.Column)
			}
			seen[key.Value] = key
		}
	}
	for _, child := range node.Content {
		if err := uniqueKeys(child); err != nil {
			return err
		}
	}
	return nil
}
