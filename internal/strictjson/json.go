// Package strictjson rejects ambiguous JSON objects and bounds nesting before
// policy, report, and evidence data cross a trust boundary.
package strictjson

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

// Decode retains json.Number values so callers can normalize numbers without
// losing integer precision. Exactly one JSON value is required.
func Decode(data []byte) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	value, err := decodeJSONValue(decoder, 0)
	if err != nil {
		// Token decoding has different syntax diagnostics from Decode. Preserve
		// the established messages for malformed inputs, while retaining our
		// duplicate-key and depth errors for otherwise valid JSON.
		var raw json.RawMessage
		if syntaxErr := json.NewDecoder(bytes.NewReader(data)).Decode(&raw); syntaxErr != nil {
			return nil, syntaxErr
		}
		return nil, err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("exactly one JSON value is required: trailing JSON value")
		}
		return nil, err
	}
	return value, nil
}

// Decode objects explicitly so conflicting or escaped duplicate names cannot
// silently replace policy inputs. Bound recursion independently of file size.
func decodeJSONValue(decoder *json.Decoder, depth int) (any, error) {
	if depth > 512 {
		return nil, fmt.Errorf("JSON nesting exceeds maximum depth 512")
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	delimiter, container := token.(json.Delim)
	if !container {
		return token, nil
	}
	switch delimiter {
	case '{':
		object := map[string]any{}
		for decoder.More() {
			token, err := decoder.Token()
			if err != nil {
				return nil, err
			}
			key, ok := token.(string)
			if !ok {
				return nil, fmt.Errorf("JSON object key must be a string")
			}
			if _, exists := object[key]; exists {
				return nil, fmt.Errorf("duplicate key %q at byte %d", key, decoder.InputOffset())
			}
			value, err := decodeJSONValue(decoder, depth+1)
			if err != nil {
				return nil, err
			}
			object[key] = value
		}
		if _, err := decoder.Token(); err != nil {
			return nil, err
		}
		return object, nil
	case '[':
		array := []any{}
		for decoder.More() {
			value, err := decodeJSONValue(decoder, depth+1)
			if err != nil {
				return nil, err
			}
			array = append(array, value)
		}
		if _, err := decoder.Token(); err != nil {
			return nil, err
		}
		return array, nil
	default:
		return nil, fmt.Errorf("unexpected JSON delimiter %q", delimiter)
	}
}
