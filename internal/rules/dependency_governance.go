package rules

import (
	"context"
	"fmt"
	pathpkg "path"
	"path/filepath"
	"strconv"
	"strings"
	"text/scanner"
	"unicode"

	"github.com/openhoo/hoolicy/internal/document"
	"github.com/openhoo/hoolicy/sdk"
)

type DependencyGovernance struct{}

type dependencyGovernanceSpec struct {
	RequireLocks             bool     `yaml:"requireLocks,omitempty"`
	ApprovedLicenses         []string `yaml:"approvedLicenses,omitempty"`
	AllowedLocalDependencies []string `yaml:"allowedLocalDependencies,omitempty"`
	Message                  string   `yaml:"message,omitempty"`
}

func (DependencyGovernance) Validate(rule sdk.Rule) error {
	if err := requireFiles(rule); err != nil {
		return err
	}
	var spec dependencyGovernanceSpec
	if err := decodeSpec(rule, &spec); err != nil {
		return err
	}
	for _, value := range append(append([]string{}, spec.ApprovedLicenses...), spec.AllowedLocalDependencies...) {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("rule %s: governance allowlists must not contain empty values", rule.ID)
		}
	}
	return nil
}

func (DependencyGovernance) Evaluate(_ context.Context, input sdk.EvalContext, rule sdk.Rule) ([]sdk.Finding, error) {
	var spec dependencyGovernanceSpec
	if err := decodeSpec(rule, &spec); err != nil {
		return nil, err
	}
	files, err := input.Repository.Match(rule.Files, rule.Exclude)
	if err != nil {
		return nil, err
	}
	message := spec.Message
	if message == "" {
		message = "Dependency manifest lacks an authoritative lock, uses unresolved source drift, or declares an unapproved license"
	}
	approved := stringSet(spec.ApprovedLicenses)
	allowedLocal := stringSet(spec.AllowedLocalDependencies)
	npmPackages, err := npmPackageInventory(files)
	if err != nil {
		return nil, err
	}
	var findings []sdk.Finding
	for _, file := range files {
		switch strings.ToLower(filepath.Base(file.Path)) {
		case "package.json":
			items, err := inspectPackageJSON(input, rule, file, spec.RequireLocks, approved, allowedLocal, npmPackages, message)
			if err != nil {
				return nil, err
			}
			findings = append(findings, items...)
		case "cargo.toml":
			items, err := inspectCargo(input, rule, file, spec.RequireLocks, approved, allowedLocal, message)
			if err != nil {
				return nil, err
			}
			findings = append(findings, items...)
		case "go.mod":
			items, err := inspectGoModule(input, rule, file, spec.RequireLocks, allowedLocal, message)
			if err != nil {
				return nil, err
			}
			findings = append(findings, items...)
		}
	}
	return findings, nil
}

func npmPackageInventory(files []sdk.File) (map[string]bool, error) {
	packages := make(map[string]bool)
	for _, file := range files {
		if strings.ToLower(filepath.Base(file.Path)) != "package.json" {
			continue
		}
		documents, _, err := document.ParseCached(file, "json")
		if err != nil {
			return nil, err
		}
		root, ok := documents[0].Data.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%s: package manifest must be an object", file.Path)
		}
		if name, _ := root["name"].(string); name != "" {
			packages[name] = true
		}
	}
	return packages, nil
}

func inspectPackageJSON(input sdk.EvalContext, rule sdk.Rule, file sdk.File, requireLock bool, approved, allowedLocal, npmPackages map[string]bool, message string) ([]sdk.Finding, error) {
	documents, hit, err := document.ParseCached(file, "json")
	if err != nil {
		return nil, err
	}
	if hit && input.Metrics != nil {
		input.Metrics.ParseCacheHits++
	}
	root, ok := documents[0].Data.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s: package manifest must be an object", file.Path)
	}
	var findings []sdk.Finding
	if requireLock {
		lockNames, manager := npmLockNames(root)
		if !hasLockAtOrAbove(input.Repository, file.Path, lockNames...) {
			detail := "package manager lock is missing"
			if manager != "" {
				detail = "authoritative " + manager + " lock is missing"
			}
			findings = append(findings, finding(rule, message+": "+detail, file.Path, "lock:missing", 1, 1))
		}
	}
	if license, ok := root["license"].(string); ok && len(approved) > 0 && !approved[license] {
		findings = append(findings, finding(rule, message+": license expression "+license+" is not approved", file.Path, "license:"+license, 1, 1))
	}
	for _, section := range []string{"dependencies", "devDependencies", "optionalDependencies", "peerDependencies"} {
		dependencies, _ := root[section].(map[string]any)
		for name, raw := range dependencies {
			value, _ := raw.(string)
			if allowedLocal[name] {
				continue
			}
			if localDependency(value) {
				if !resolvedNPMLocal(input.Repository, file.Path, name, value, npmPackages) {
					findings = append(findings, finding(rule, message+": "+name+" uses unresolved local reference "+value, file.Path, section+":"+name+":local", 1, 1))
				}
				continue
			}
			if driftingDependency(value) {
				findings = append(findings, finding(rule, message+": "+name+" uses mutable source "+value, file.Path, section+":"+name+":source", 1, 1))
			}
		}
	}
	return findings, nil
}

func npmLockNames(manifest map[string]any) ([]string, string) {
	manager, _ := manifest["packageManager"].(string)
	name, _, _ := strings.Cut(manager, "@")
	switch name {
	case "npm":
		return []string{"package-lock.json", "npm-shrinkwrap.json"}, name
	case "pnpm":
		return []string{"pnpm-lock.yaml"}, name
	case "yarn":
		return []string{"yarn.lock"}, name
	case "bun":
		return []string{"bun.lock", "bun.lockb"}, name
	case "":
		return []string{"package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock", "bun.lockb"}, ""
	default:
		return nil, name
	}
}

func inspectCargo(input sdk.EvalContext, rule sdk.Rule, file sdk.File, requireLock bool, approved, allowedLocal map[string]bool, message string) ([]sdk.Finding, error) {
	documents, hit, err := document.ParseCached(file, "toml")
	if err != nil {
		return nil, err
	}
	if hit && input.Metrics != nil {
		input.Metrics.ParseCacheHits++
	}
	root, _ := documents[0].Data.(map[string]any)
	var findings []sdk.Finding
	if requireLock && !hasLockAtOrAbove(input.Repository, file.Path, "Cargo.lock") {
		findings = append(findings, finding(rule, message+": Cargo.lock is missing", file.Path, "lock:missing", 1, 1))
	}
	packageInfo, _ := root["package"].(map[string]any)
	if license, ok := packageInfo["license"].(string); ok && len(approved) > 0 && !approved[license] {
		findings = append(findings, finding(rule, message+": license expression "+license+" is not approved", file.Path, "license:"+license, 1, 1))
	}
	for _, section := range []string{"dependencies", "dev-dependencies", "build-dependencies"} {
		dependencies, _ := root[section].(map[string]any)
		for name, raw := range dependencies {
			if allowedLocal[name] {
				continue
			}
			entry, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			if localPath, _ := entry["path"].(string); localPath != "" && !referencedRepositoryPathExists(input.Repository, file.Path, localPath, "Cargo.toml") {
				findings = append(findings, finding(rule, message+": "+name+" uses unresolved local path "+localPath, file.Path, section+":"+name+":local", 1, 1))
			}
			if git, _ := entry["git"].(string); git != "" {
				rev, _ := entry["rev"].(string)
				if !fullCommitRef.MatchString(rev) {
					findings = append(findings, finding(rule, message+": "+name+" Git source lacks a full commit rev", file.Path, section+":"+name+":source", 1, 1))
				}
			}
		}
	}
	return findings, nil
}

func inspectGoModule(input sdk.EvalContext, rule sdk.Rule, file sdk.File, requireLock bool, allowedLocal map[string]bool, message string) ([]sdk.Finding, error) {
	var findings []sdk.Finding
	if requireLock && !hasSibling(input.Repository, file.Path, "go.sum") {
		findings = append(findings, finding(rule, message+": go.sum is missing", file.Path, "lock:missing", 1, 1))
	}
	inReplaceBlock := false
	for index, line := range strings.Split(string(file.Data), "\n") {
		fields, err := goModuleFields(line)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %w", file.Path, index+1, err)
		}
		if len(fields) == 0 {
			continue
		}
		if fields[0] == "replace" {
			fields = fields[1:]
			if len(fields) > 0 && fields[0] == "(" {
				inReplaceBlock = true
				fields = fields[1:]
			}
		} else if !inReplaceBlock {
			continue
		}
		if len(fields) > 0 && fields[len(fields)-1] == ")" {
			inReplaceBlock = false
			fields = fields[:len(fields)-1]
		}
		if len(fields) == 0 {
			continue
		}
		arrow := -1
		for position, field := range fields {
			if field == "=>" {
				arrow = position
				break
			}
		}
		if arrow < 1 || arrow+1 >= len(fields) {
			return nil, fmt.Errorf("%s:%d: malformed replace directive", file.Path, index+1)
		}
		module, target := fields[0], fields[arrow+1]
		if !allowedLocal[module] && localGoReplacement(target) {
			findings = append(findings, finding(rule, message+": "+module+" uses unresolved local replace "+target, file.Path, "replace:"+module, index+1, 1))
		}
	}
	if inReplaceBlock {
		return nil, fmt.Errorf("%s: unclosed replace block", file.Path)
	}
	return findings, nil
}

// goModuleFields preserves quoted local paths and discards comments. Scanner
// handles string escapes; punctuation stays in words except block delimiters.
func goModuleFields(line string) ([]string, error) {
	var lexer scanner.Scanner
	lexer.Init(strings.NewReader(line))
	lexer.Mode = scanner.ScanStrings | scanner.ScanRawStrings | scanner.ScanComments
	lexer.Whitespace = 0
	var scanErr error
	lexer.Error = func(_ *scanner.Scanner, message string) { scanErr = fmt.Errorf("invalid Go module token: %s", message) }
	var fields []string
	var word strings.Builder
	flush := func() {
		if word.Len() > 0 {
			fields = append(fields, word.String())
			word.Reset()
		}
	}
	for token := lexer.Scan(); token != scanner.EOF; token = lexer.Scan() {
		switch {
		case token == scanner.Comment:
			flush()
		case token == scanner.String || token == scanner.RawString:
			flush()
			value, err := strconv.Unquote(lexer.TokenText())
			if err != nil {
				return nil, err
			}
			fields = append(fields, value)
		case unicode.IsSpace(token):
			flush()
		case token == '(' || token == ')':
			flush()
			fields = append(fields, string(token))
		default:
			word.WriteString(lexer.TokenText())
		}
	}
	flush()
	return fields, scanErr
}

func localGoReplacement(target string) bool {
	return strings.HasPrefix(target, "./") || strings.HasPrefix(target, "../") || strings.HasPrefix(target, "/") || filepath.IsAbs(target) || windowsVolume(target) || strings.Contains(target, "\\")
}

func hasSibling(repository sdk.Repository, manifest string, names ...string) bool {
	directory := filepath.ToSlash(filepath.Dir(manifest))
	if directory == "." {
		directory = ""
	}
	for _, name := range names {
		path := filepath.ToSlash(filepath.Join(directory, name))
		if _, err := repository.Read(path); err == nil {
			return true
		}
	}
	return false
}

func hasLockAtOrAbove(repository sdk.Repository, manifest string, names ...string) bool {
	directory := pathpkg.Dir(manifest)
	for {
		for _, name := range names {
			candidate := name
			if directory != "." {
				candidate = pathpkg.Join(directory, name)
			}
			if _, err := repository.Read(candidate); err == nil {
				return true
			}
		}
		if directory == "." {
			return false
		}
		directory = pathpkg.Dir(directory)
	}
}

func resolvedNPMLocal(repository sdk.Repository, manifest, name, value string, packages map[string]bool) bool {
	if strings.HasPrefix(value, "workspace:") {
		return packages[name]
	}
	target := strings.TrimPrefix(strings.TrimPrefix(value, "file:"), "link:")
	return referencedRepositoryPathExists(repository, manifest, target, "package.json") || referencedRepositoryFileExists(repository, manifest, target)
}

func referencedRepositoryPathExists(repository sdk.Repository, manifest, target, child string) bool {
	resolved, ok := repositoryRelativeReference(manifest, target)
	if !ok {
		return false
	}
	_, err := repository.Read(pathpkg.Join(resolved, child))
	return err == nil
}

func referencedRepositoryFileExists(repository sdk.Repository, manifest, target string) bool {
	resolved, ok := repositoryRelativeReference(manifest, target)
	if !ok {
		return false
	}
	_, err := repository.Read(resolved)
	return err == nil
}

func repositoryRelativeReference(manifest, target string) (string, bool) {
	trimmed := strings.TrimSpace(target)
	if trimmed == "" || trimmed != target || strings.HasPrefix(target, "/") || filepath.IsAbs(target) || windowsVolume(target) || strings.ContainsAny(target, "\\\x00") {
		return "", false
	}
	target = filepath.ToSlash(target)
	resolved := pathpkg.Clean(pathpkg.Join(pathpkg.Dir(manifest), target))
	if resolved == ".." || strings.HasPrefix(resolved, "../") {
		return "", false
	}
	return resolved, true
}

func stringSet(values []string) map[string]bool {
	result := map[string]bool{}
	for _, value := range values {
		result[value] = true
	}
	return result
}
func localDependency(value string) bool {
	return strings.HasPrefix(value, "file:") || strings.HasPrefix(value, "link:") || strings.HasPrefix(value, "workspace:")
}
func driftingDependency(value string) bool {
	if strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://") {
		return true
	}
	if strings.HasPrefix(value, "git+") || strings.HasPrefix(value, "github:") {
		_, fragment, found := strings.Cut(value, "#")
		return !found || !fullCommitRef.MatchString(fragment)
	}
	return false
}
