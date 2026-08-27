package repository

import (
	"fmt"
	"regexp"
	"strings"
)

func compileGlob(pattern string) (*regexp.Regexp, error) {
	pattern = strings.TrimPrefix(strings.ReplaceAll(pattern, "\\", "/"), "./")
	if pattern == "" {
		return nil, fmt.Errorf("empty glob")
	}
	var expression strings.Builder
	expression.WriteString("^")
	for i := 0; i < len(pattern); {
		switch pattern[i] {
		case '*':
			if i+1 < len(pattern) && pattern[i+1] == '*' {
				i += 2
				if i < len(pattern) && pattern[i] == '/' {
					expression.WriteString("(?:.*/)?")
					i++
				} else {
					expression.WriteString(".*")
				}
			} else {
				expression.WriteString("[^/]*")
				i++
			}
		case '?':
			expression.WriteString("[^/]")
			i++
		case '[':
			end := strings.IndexByte(pattern[i+1:], ']')
			if end < 0 {
				return nil, fmt.Errorf("unterminated character class in %q", pattern)
			}
			end += i + 1
			class := pattern[i+1 : end]
			if strings.HasPrefix(class, "!") {
				class = "^" + class[1:]
			}
			expression.WriteByte('[')
			expression.WriteString(class)
			expression.WriteByte(']')
			i = end + 1
		case '{':
			end := strings.IndexByte(pattern[i+1:], '}')
			if end < 0 {
				return nil, fmt.Errorf("unterminated alternation in %q", pattern)
			}
			end += i + 1
			parts := strings.Split(pattern[i+1:end], ",")
			if len(parts) < 2 {
				return nil, fmt.Errorf("alternation in %q needs at least two values", pattern)
			}
			expression.WriteString("(?:")
			for index, part := range parts {
				if index > 0 {
					expression.WriteByte('|')
				}
				expression.WriteString(regexp.QuoteMeta(part))
			}
			expression.WriteByte(')')
			i = end + 1
		default:
			expression.WriteString(regexp.QuoteMeta(string(pattern[i])))
			i++
		}
	}
	expression.WriteString("$")
	compiled, err := regexp.Compile(expression.String())
	if err != nil {
		return nil, fmt.Errorf("invalid glob %q: %w", pattern, err)
	}
	return compiled, nil
}

func matchesAny(path string, patterns []string) (bool, error) {
	compiled, err := compileGlobs(patterns)
	if err != nil {
		return false, err
	}
	return matchesCompiled(path, compiled), nil
}

func compileGlobs(patterns []string) ([]*regexp.Regexp, error) {
	compiled := make([]*regexp.Regexp, 0, len(patterns))
	for _, pattern := range patterns {
		expression, err := compileGlob(pattern)
		if err != nil {
			return nil, err
		}
		compiled = append(compiled, expression)
	}
	return compiled, nil
}

func matchesCompiled(path string, patterns []*regexp.Regexp) bool {
	path = strings.TrimPrefix(strings.ReplaceAll(path, "\\", "/"), "./")
	for _, pattern := range patterns {
		if pattern.MatchString(path) {
			return true
		}
	}
	return false
}

func Matches(path string, patterns []string) (bool, error) {
	return matchesAny(path, patterns)
}
