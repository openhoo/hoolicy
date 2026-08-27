// Command sync_release_version keeps user-facing release examples aligned with VERSION.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var semanticVersion = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)

type replacement struct {
	pattern     *regexp.Regexp
	replacement string
}

func main() {
	if err := syncReleaseVersion("."); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func syncReleaseVersion(root string) error {
	rawVersion, err := os.ReadFile(filepath.Join(root, "VERSION"))
	if err != nil {
		return fmt.Errorf("read VERSION: %w", err)
	}
	version := strings.TrimSpace(string(rawVersion))
	if !semanticVersion.MatchString(version) {
		return fmt.Errorf("VERSION must contain one semantic version, got %q", version)
	}
	majorMinor := strings.Join(strings.Split(version, ".")[:2], ".")

	if err := updateFile(filepath.Join(root, "README.md"), []replacement{
		{regexp.MustCompile(`(?m)^([^\r\n]*github\.com/openhoo/hoolicy/cmd/hoolicy@)v[0-9]+\.[0-9]+\.[0-9]+([^\r\n]*)$`), "${1}v" + version + "${2}"},
		{regexp.MustCompile(`(?m)^([^\r\n]*ghcr\.io/openhoo/hoolicy:)v[0-9]+\.[0-9]+\.[0-9]+([^\r\n]*)$`), "${1}v" + version + "${2}"},
		{regexp.MustCompile(`(?m)^([\t ]*ref: )v[0-9]+\.[0-9]+\.[0-9]+([\t ]*)$`), "${1}v" + version + "${2}"},
	}); err != nil {
		return err
	}

	return updateFile(filepath.Join(root, "SECURITY.md"), []replacement{
		{regexp.MustCompile("(?m)^([^\\r\\n]*latest `)v[0-9]+\\.[0-9]+\\.x(` release[^\\r\\n]*)$"), "${1}v" + majorMinor + ".x${2}"},
	})
}

func updateFile(path string, replacements []replacement) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", filepath.Base(path), err)
	}
	updated := string(raw)
	for _, item := range replacements {
		if !item.pattern.MatchString(updated) {
			return fmt.Errorf("%s: expected version marker %q", filepath.Base(path), item.pattern.String())
		}
		updated = item.pattern.ReplaceAllString(updated, item.replacement)
	}
	if updated == string(raw) {
		return nil
	}
	if err := os.WriteFile(path, []byte(updated), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", filepath.Base(path), err)
	}
	return nil
}
