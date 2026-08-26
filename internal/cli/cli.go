package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/openhoo/hoolicy/internal/config"
	"github.com/openhoo/hoolicy/internal/engine"
	"github.com/openhoo/hoolicy/internal/fix"
	"github.com/openhoo/hoolicy/internal/packs"
	"github.com/openhoo/hoolicy/internal/policytest"
	"github.com/openhoo/hoolicy/internal/report"
	"github.com/openhoo/hoolicy/internal/rules"
	"github.com/openhoo/hoolicy/sdk"
)

type BuildInfo struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
	Date    string `json:"date"`
}

type application struct {
	stdout   io.Writer
	stderr   io.Writer
	info     BuildInfo
	registry *sdk.Registry
	engine   *engine.Engine
}

func Run(ctx context.Context, args []string, info BuildInfo) int {
	registry := sdk.NewRegistry()
	if err := rules.RegisterCore(registry); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	return RunWithRegistry(ctx, args, info, registry)
}

func RunWithRegistry(ctx context.Context, args []string, info BuildInfo, registry *sdk.Registry) int {
	if registry == nil {
		fmt.Fprintln(os.Stderr, "hoolicy: registry is required")
		return 2
	}
	app := application{stdout: os.Stdout, stderr: os.Stderr, info: info, registry: registry, engine: engine.New(registry)}
	return app.run(ctx, args)
}

func (a application) run(ctx context.Context, args []string) int {
	if len(args) == 0 {
		return a.help()
	}
	switch args[0] {
	case "help", "-h", "--help":
		return a.help()
	case "version", "--version":
		return a.version(args[1:])
	case "init":
		return a.init(args[1:])
	case "validate":
		return a.validate(args[1:])
	case "check":
		return a.check(ctx, args[1:])
	case "fix":
		return a.fix(ctx, args[1:])
	case "list":
		return a.list(args[1:])
	case "explain":
		return a.explain(args[1:])
	case "test":
		return a.test(ctx, args[1:])
	case "pack":
		return a.pack(ctx, args[1:])
	default:
		fmt.Fprintf(a.stderr, "Unknown command %q. Run 'hoolicy help'.\n", args[0])
		return 2
	}
}

func (a application) help() int {
	fmt.Fprint(a.stdout, `Hoolicy — understandable, reproducible policy as code

Usage:
  hoolicy <command> [options]

Commands:
  init       Create a strict starter configuration
  validate   Validate configuration, packs, and rule expressions
  check      Evaluate all policies offline
  fix        Preview or apply engine-approved safe fixes
  list       List active rules
  explain    Explain one active rule
  test       Run policy pack fixtures
  pack       Add, update, or verify policy packs
  version    Print build information

Run 'hoolicy <command> -h' for command options.
`)
	return 0
}

func (a application) version(args []string) int {
	flags := flag.NewFlagSet("version", flag.ContinueOnError)
	flags.SetOutput(a.stderr)
	asJSON := flags.Bool("json", false, "print machine-readable build information")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *asJSON {
		_ = json.NewEncoder(a.stdout).Encode(a.info)
		return 0
	}
	fmt.Fprintf(a.stdout, "hoolicy %s (commit %s, built %s)\n", a.info.Version, a.info.Commit, a.info.Date)
	return 0
}

func (a application) init(args []string) int {
	flags := flag.NewFlagSet("init", flag.ContinueOnError)
	flags.SetOutput(a.stderr)
	projectName := flags.String("project", "", "lowercase project name")
	directory := flags.String("directory", ".", "target directory")
	profile := flags.String("profile", "standard", "starter profile: empty, standard, or strict")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	root, err := filepath.Abs(*directory)
	if err != nil {
		return a.fail(err)
	}
	if *projectName == "" {
		*projectName = strings.ToLower(filepath.Base(root))
		*projectName = strings.NewReplacer(" ", "-", "_", "-").Replace(*projectName)
	}
	path := filepath.Join(root, config.DefaultFilename)
	if _, err := os.Stat(path); err == nil {
		return a.fail(fmt.Errorf("%s already exists", path))
	}
	starter, err := starterRules(*profile)
	if err != nil {
		return a.fail(err)
	}
	project := config.Project{Version: 1, Project: *projectName, FailOn: sdk.SeverityError, Waivers: config.DefaultWaivers, Rules: starter}
	if err := project.Validate(); err != nil {
		return a.fail(err)
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		return a.fail(err)
	}
	if err := config.SaveProject(path, project); err != nil {
		return a.fail(err)
	}
	waiverPath := filepath.Join(root, filepath.FromSlash(config.DefaultWaivers))
	if err := os.MkdirAll(filepath.Dir(waiverPath), 0o755); err != nil {
		return a.fail(err)
	}
	if err := os.WriteFile(waiverPath, []byte("version: 1\nwaivers: []\n"), 0o644); err != nil {
		return a.fail(err)
	}
	fmt.Fprintf(a.stdout, "Created %s and %s with %d %s rules. Run 'hoolicy check'.\n", path, waiverPath, len(starter), *profile)
	return 0
}

func (a application) validate(args []string) int {
	flags := flag.NewFlagSet("validate", flag.ContinueOnError)
	flags.SetOutput(a.stderr)
	configPath := flags.String("config", "", "configuration path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	project, err := loadProject(*configPath)
	if err != nil {
		return a.fail(err)
	}
	active, err := a.engine.Validate(project)
	if err != nil {
		return a.fail(err)
	}
	fmt.Fprintf(a.stdout, "Configuration valid: %d active rules.\n", len(active))
	return 0
}

func (a application) check(ctx context.Context, args []string) int {
	flags := flag.NewFlagSet("check", flag.ContinueOnError)
	flags.SetOutput(a.stderr)
	configPath := flags.String("config", "", "configuration path")
	format := flags.String("format", "text", "text, json, sarif, or junit")
	output := flags.String("output", "", "write report to file")
	base := flags.String("base", envFirst("HOOLICY_BASE_SHA", "CI_MERGE_REQUEST_DIFF_BASE_SHA"), "base commit for commit-range checks")
	mrTitle := flags.String("merge-request-title", envFirst("HOOLICY_MERGE_REQUEST_TITLE", "CI_MERGE_REQUEST_TITLE"), "merge request title")
	failOn := flags.String("fail-on", "", "use an equal or stricter failure threshold")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	project, err := loadProject(*configPath)
	if err != nil {
		return a.fail(err)
	}
	if *failOn != "" {
		candidate := sdk.Severity(*failOn)
		if !candidate.Valid() {
			return a.fail(fmt.Errorf("invalid --fail-on %q", *failOn))
		}
		if candidate.Rank() < project.FailOn.Rank() {
			project.FailOn = candidate
		} else if candidate.Rank() > project.FailOn.Rank() {
			return a.fail(fmt.Errorf("--fail-on may not weaken project threshold %s", project.FailOn))
		}
	}
	result, err := a.engine.Check(ctx, project, engine.Options{BaseSHA: *base, MergeRequestTitle: *mrTitle, ToolVersion: a.info.Version})
	if err != nil {
		return a.fail(err)
	}
	writer := a.stdout
	var file *os.File
	if *output != "" {
		file, err = os.Create(*output)
		if err != nil {
			return a.fail(err)
		}
		defer file.Close()
		writer = file
	}
	if err := report.Write(writer, *format, result, colorEnabled(a.stdout)); err != nil {
		return a.fail(err)
	}
	if result.Summary.Blocking > 0 {
		return 1
	}
	return 0
}

func (a application) fix(ctx context.Context, args []string) int {
	flags := flag.NewFlagSet("fix", flag.ContinueOnError)
	flags.SetOutput(a.stderr)
	configPath := flags.String("config", "", "configuration path")
	apply := flags.Bool("apply", false, "apply the exact previewed safe fixes")
	base := flags.String("base", envFirst("HOOLICY_BASE_SHA", "CI_MERGE_REQUEST_DIFF_BASE_SHA"), "base commit")
	mrTitle := flags.String("merge-request-title", envFirst("HOOLICY_MERGE_REQUEST_TITLE", "CI_MERGE_REQUEST_TITLE"), "merge request title")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	project, err := loadProject(*configPath)
	if err != nil {
		return a.fail(err)
	}
	result, err := a.engine.Check(ctx, project, engine.Options{BaseSHA: *base, MergeRequestTitle: *mrTitle, ToolVersion: a.info.Version})
	if err != nil {
		return a.fail(err)
	}
	plan, err := fix.Build(project.Root, result.Findings, flags.Args())
	if err != nil {
		return a.fail(err)
	}
	fmt.Fprint(a.stdout, plan.Diff())
	if !*apply {
		fmt.Fprintln(a.stdout, "Preview only. Re-run with --apply after reviewing this diff.")
		return 0
	}
	if err := plan.Apply(); err != nil {
		return a.fail(err)
	}
	fmt.Fprintf(a.stdout, "Applied safe fixes to %d files.\n", len(plan.Files))
	return 0
}

func (a application) list(args []string) int {
	flags := flag.NewFlagSet("list", flag.ContinueOnError)
	flags.SetOutput(a.stderr)
	configPath := flags.String("config", "", "configuration path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	project, err := loadProject(*configPath)
	if err != nil {
		return a.fail(err)
	}
	active, err := a.engine.Validate(project)
	if err != nil {
		return a.fail(err)
	}
	for _, rule := range active {
		source := "project"
		if rule.Pack != "" {
			source = rule.Pack + "@" + rule.PackVersion
		}
		fmt.Fprintf(a.stdout, "%-8s %-30s %-24s %s\n", rule.Severity, rule.ID, source, rule.Title)
	}
	return 0
}

func (a application) explain(args []string) int {
	flags := flag.NewFlagSet("explain", flag.ContinueOnError)
	flags.SetOutput(a.stderr)
	configPath := flags.String("config", "", "configuration path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 1 {
		return a.fail(fmt.Errorf("usage: hoolicy explain [--config path] <rule-id>"))
	}
	project, err := loadProject(*configPath)
	if err != nil {
		return a.fail(err)
	}
	active, err := a.engine.Validate(project)
	if err != nil {
		return a.fail(err)
	}
	for _, rule := range active {
		if rule.ID != flags.Arg(0) {
			continue
		}
		fmt.Fprintf(a.stdout, "%s — %s\n\nSeverity: %s\nKind: %s\nSource: %s@%s\n\n%s\n\nWhy: %s\n\nFix: %s\n", rule.ID, rule.Title, rule.Severity, rule.Kind, fallback(rule.Pack, "project"), fallback(rule.PackVersion, "local"), rule.Description, rule.Rationale, rule.Remediation)
		if len(rule.Controls) > 0 {
			fmt.Fprintln(a.stdout, "\nControls:")
			for _, control := range rule.Controls {
				fmt.Fprintf(a.stdout, "- %s %s\n", control.Framework, control.ID)
			}
		}
		return 0
	}
	return a.fail(fmt.Errorf("unknown rule %s", flags.Arg(0)))
}

func (a application) test(ctx context.Context, args []string) int {
	flags := flag.NewFlagSet("test", flag.ContinueOnError)
	flags.SetOutput(a.stderr)
	if err := flags.Parse(args); err != nil {
		return 2
	}
	paths := flags.Args()
	if len(paths) == 0 {
		paths = []string{"."}
	}
	total, passed := 0, 0
	var problems []string
	for _, path := range paths {
		result := policytest.Run(ctx, path, a.registry)
		total += result.Cases
		passed += result.Passed
		for _, problem := range result.Errors {
			problems = append(problems, path+": "+problem)
		}
	}
	for _, problem := range problems {
		fmt.Fprintln(a.stderr, problem)
	}
	fmt.Fprintf(a.stdout, "Policy tests: %d/%d passed.\n", passed, total)
	if len(problems) > 0 {
		return 1
	}
	return 0
}

func (a application) pack(ctx context.Context, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(a.stderr, "usage: hoolicy pack add|update|verify")
		return 2
	}
	switch args[0] {
	case "add":
		return a.packAdd(args[1:])
	case "update":
		return a.packUpdate(args[1:])
	case "verify":
		return a.packVerify(ctx, args[1:])
	default:
		return a.fail(fmt.Errorf("unknown pack command %s", args[0]))
	}
}

func (a application) packAdd(args []string) int {
	flags := flag.NewFlagSet("pack add", flag.ContinueOnError)
	flags.SetOutput(a.stderr)
	configPath := flags.String("config", "", "configuration path")
	gitURL := flags.String("git", "", "Git repository URL")
	ref := flags.String("ref", "", "Git tag, branch, or commit")
	subdir := flags.String("subdir", "", "pack subdirectory")
	local := flags.String("path", "", "local pack path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 1 {
		return a.fail(fmt.Errorf("usage: hoolicy pack add [options] <name>"))
	}
	project, err := loadProject(*configPath)
	if err != nil {
		return a.fail(err)
	}
	name := flags.Arg(0)
	for _, entry := range project.Packs {
		if entry.Name == name {
			return a.fail(fmt.Errorf("pack %s already exists", name))
		}
	}
	reference := config.PackRef{Name: name, Path: *local, Git: *gitURL, Ref: *ref, Subdir: *subdir}
	project.Packs = append(project.Packs, reference)
	if err := project.Validate(); err != nil {
		return a.fail(err)
	}
	if reference.Git != "" {
		if _, err := packs.UpdateLock(project, []string{name}); err != nil {
			return a.fail(err)
		}
	} else {
		if _, err := config.LoadPack(filepath.Join(project.Root, filepath.FromSlash(reference.Path))); err != nil {
			return a.fail(err)
		}
	}
	if err := config.SaveProject(project.Path, *project); err != nil {
		return a.fail(err)
	}
	fmt.Fprintf(a.stdout, "Added pack %s. Review %s and %s before committing.\n", name, config.DefaultFilename, config.DefaultLockfile)
	return 0
}

func (a application) packUpdate(args []string) int {
	flags := flag.NewFlagSet("pack update", flag.ContinueOnError)
	flags.SetOutput(a.stderr)
	configPath := flags.String("config", "", "configuration path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	project, err := loadProject(*configPath)
	if err != nil {
		return a.fail(err)
	}
	names := flags.Args()
	if len(names) == 0 {
		for _, entry := range project.Packs {
			if entry.Git != "" {
				names = append(names, entry.Name)
			}
		}
	}
	if len(names) == 0 {
		return a.fail(fmt.Errorf("no remote packs selected"))
	}
	sort.Strings(names)
	if _, err := packs.UpdateLock(project, names); err != nil {
		return a.fail(err)
	}
	fmt.Fprintf(a.stdout, "Updated and verified %d packs. Review vendored changes and %s.\n", len(names), config.DefaultLockfile)
	return 0
}

func (a application) packVerify(ctx context.Context, args []string) int {
	flags := flag.NewFlagSet("pack verify", flag.ContinueOnError)
	flags.SetOutput(a.stderr)
	configPath := flags.String("config", "", "configuration path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() > 0 {
		code := a.test(ctx, flags.Args())
		if code != 0 {
			return code
		}
		for _, path := range flags.Args() {
			digest, err := packs.Digest(path)
			if err != nil {
				return a.fail(err)
			}
			fmt.Fprintf(a.stdout, "%s %s\n", digest, path)
		}
		return 0
	}
	project, err := loadProject(*configPath)
	if err != nil {
		return a.fail(err)
	}
	active, err := a.engine.Validate(project)
	if err != nil {
		return a.fail(err)
	}
	fmt.Fprintf(a.stdout, "Verified %d active rules and all vendored pack digests.\n", len(active))
	return 0
}

func loadProject(explicit string) (*config.Project, error) {
	path, err := config.Find(".", explicit)
	if err != nil {
		return nil, err
	}
	return config.LoadProject(path)
}
func (a application) fail(err error) int { fmt.Fprintln(a.stderr, "hoolicy:", err); return 2 }
func envFirst(names ...string) string {
	for _, name := range names {
		if value := os.Getenv(name); value != "" {
			return value
		}
	}
	return ""
}
func fallback(value, defaultValue string) string {
	if strings.TrimSpace(value) == "" {
		return defaultValue
	}
	return value
}
func colorEnabled(writer io.Writer) bool {
	if os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return false
	}
	file, ok := writer.(*os.File)
	if !ok {
		return false
	}
	info, err := file.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func starterRules(profile string) ([]sdk.Rule, error) {
	if profile == "empty" {
		return []sdk.Rule{}, nil
	}
	if profile != "standard" && profile != "strict" {
		return nil, fmt.Errorf("unknown starter profile %q", profile)
	}
	rule := func(id, title, description, rationale, remediation, kind string, files []string, spec map[string]any) sdk.Rule {
		return sdk.Rule{
			ID: id, Title: title, Description: description, Rationale: rationale,
			Remediation: remediation, Severity: sdk.SeverityError, Kind: kind, Files: files, Spec: spec,
		}
	}
	rules := []sdk.Rule{
		rule("repository.readme", "Repository has an entry point", "Requires a README at the repository root.", "Contributors need discoverable setup and operating context.", "Add a reviewed README.md.", "files", []string{"README.md"}, map[string]any{"mode": "require", "message": "README.md is required"}),
		rule("repository.license", "Repository declares its license", "Requires a license file at the repository root.", "Explicit licensing removes ambiguity for users and contributors.", "Add the license approved for this project.", "files", []string{"LICENSE", "LICENSE.*"}, map[string]any{"mode": "require", "message": "A license file is required"}),
		rule("repository.security-policy", "Repository documents vulnerability reporting", "Requires a SECURITY.md at the repository root.", "A documented private reporting path reduces unsafe public disclosure.", "Add a reviewed SECURITY.md with supported versions and contact instructions.", "files", []string{"SECURITY.md"}, map[string]any{"mode": "require", "message": "SECURITY.md is required"}),
		rule("repository.git-naming", "Git names use Conventional Commits", "Checks local branch and commit names with one portable convention.", "Machine-enforced naming keeps history searchable across Git providers.", "Rename the branch or commit using the documented convention.", "git.naming", nil, map[string]any{
			"branchPattern":   `^(feat|fix|docs|style|refactor|perf|test|build|ci|chore|revert)/[a-z0-9]+(?:-[a-z0-9]+)*$`,
			"allowedBranches": []string{"main", "master"},
			"commitPattern":   `^(feat|fix|docs|style|refactor|perf|test|build|ci|chore|revert)(\([a-z0-9][a-z0-9-]*\))?!?: .+$`,
			"message":         "Git name does not follow the repository convention",
		}),
		rule("supply-chain.approved-sources", "Dependencies use approved public sources", "Parses common package and container source declarations.", "Explicit source boundaries reduce dependency-confusion and accidental registry drift.", "Mirror the artifact into an approved source or adjust the reviewed allowlist.", "sources.allowed", []string{"**/.npmrc", "**/nuget.config", "**/{Dockerfile,Containerfile}", "**/{Dockerfile,Containerfile}.*", "**/*.{json,yaml,yml}"}, map[string]any{
			"registries": []string{"docker.io", "ghcr.io"}, "npm": []string{"https://registry.npmjs.org"},
			"nuget": []string{"https://api.nuget.org/v3/index.json"}, "requireDigest": profile == "strict",
			"message": "Artifact source is outside the approved supply chain",
		}),
	}
	return rules, nil
}
