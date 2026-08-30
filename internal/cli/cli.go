package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/openhoo/hoolicy/internal/config"
	"github.com/openhoo/hoolicy/internal/engine"
	"github.com/openhoo/hoolicy/internal/evidence"
	"github.com/openhoo/hoolicy/internal/fix"
	"github.com/openhoo/hoolicy/internal/ocipack"
	"github.com/openhoo/hoolicy/internal/packarchive"
	"github.com/openhoo/hoolicy/internal/packs"
	"github.com/openhoo/hoolicy/internal/policylint"
	"github.com/openhoo/hoolicy/internal/policytest"
	"github.com/openhoo/hoolicy/internal/report"
	"github.com/openhoo/hoolicy/internal/repository"
	"github.com/openhoo/hoolicy/internal/rules"
	"github.com/openhoo/hoolicy/internal/safepath"
	"github.com/openhoo/hoolicy/sdk"
	"go.yaml.in/yaml/v3"
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
	app := application{stdout: os.Stdout, stderr: os.Stderr, info: info, registry: registry, engine: engine.NewWithVersion(registry, info.Version)}
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
	case "baseline":
		return a.baseline(ctx, args[1:])
	case "doctor":
		return a.doctor(ctx, args[1:])
	case "report":
		return a.report(args[1:])
	case "fmt":
		return a.format(args[1:])
	case "lint":
		return a.lint(args[1:])
	case "completion":
		return a.completion(args[1:])
	case "evidence":
		return a.evidence(ctx, args[1:])
	case "waiver":
		return a.waiver(ctx, args[1:])
	case "inventory":
		return a.inventory(ctx, args[1:])
	case "serve":
		return a.serve(ctx, args[1:])
	case "migrate":
		return a.migrate(args[1:])
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
  init       Create a standard, strict, or empty starter configuration
  validate   Validate configuration, packs, and rule expressions
  check      Evaluate all policies offline
  fix        Preview or apply engine-approved safe fixes
  list       List active rules
  explain    Explain one active rule
  test       Run policy pack fixtures
  baseline   Create or prune reviewed finding baselines
  doctor     Diagnose local policy and CI inputs without changing files
  report     Compare deterministic JSON reports
  fmt        Normalize Hoolicy-owned YAML
  lint       Explain pack-authoring heuristics
  completion Generate shell completion scripts
  evidence   Create or independently verify decision evidence
  waiver     Preview or apply an exact finding-bound waiver
  inventory  Emit active workspace, rule, control, waiver, and owner inventory
  serve      Run a loopback-only, GET-only policy service
  migrate    Preview or apply supported on-disk format migrations
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
		return flagErrorCode(err)
	}
	if flags.NArg() != 0 {
		return a.unexpectedArguments("version", flags.Args())
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
		return flagErrorCode(err)
	}
	if flags.NArg() != 0 {
		return a.unexpectedArguments("init", flags.Args())
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
	waiverPath := filepath.Join(root, filepath.FromSlash(config.DefaultWaivers))
	for _, candidate := range []string{path, waiverPath} {
		if _, err := os.Lstat(candidate); err == nil {
			return a.fail(fmt.Errorf("%s already exists", candidate))
		} else if !os.IsNotExist(err) {
			return a.fail(err)
		}
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
	_, waiverPath, err = safepath.Writable(root, config.DefaultWaivers)
	if err != nil {
		return a.fail(fmt.Errorf("unsafe waiver path: %w", err))
	}
	if err := config.SaveProject(path, project); err != nil {
		return a.fail(err)
	}
	if err := config.SaveWaivers(waiverPath, config.WaiverFile{Version: config.CurrentVersion, Waivers: []config.Waiver{}}); err != nil {
		if rollbackErr := os.Remove(path); rollbackErr != nil && !errors.Is(rollbackErr, os.ErrNotExist) {
			return a.fail(fmt.Errorf("create waiver file: %w; remove incomplete configuration %s: %v", err, path, rollbackErr))
		}
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
		return flagErrorCode(err)
	}
	if flags.NArg() != 0 {
		return a.unexpectedArguments("validate", flags.Args())
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
	format := flags.String("format", "text", "text, json, sarif, junit, github, or gitlab-codequality")
	output := flags.String("output", "", "write report to file")
	base := flags.String("base", envFirst("HOOLICY_BASE_SHA", "CI_MERGE_REQUEST_DIFF_BASE_SHA"), "base commit for commit-range checks")
	mrTitle := flags.String("merge-request-title", envFirst("HOOLICY_MERGE_REQUEST_TITLE", "CI_MERGE_REQUEST_TITLE"), "merge request title")
	failOn := flags.String("fail-on", "", "use an equal or stricter failure threshold")
	if err := flags.Parse(args); err != nil {
		return flagErrorCode(err)
	}
	if flags.NArg() != 0 {
		return a.unexpectedArguments("check", flags.Args())
	}
	if !report.ValidFormat(*format) {
		return a.fail(fmt.Errorf("unknown report format %q", *format))
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
	if *output != "" {
		var encoded bytes.Buffer
		if err := report.Write(&encoded, *format, result, false); err != nil {
			return a.fail(err)
		}
		if err := writeReportFile(*output, encoded.Bytes()); err != nil {
			return a.fail(err)
		}
	} else if err := report.Write(a.stdout, *format, result, colorEnabled(a.stdout)); err != nil {
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
		return flagErrorCode(err)
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
		return flagErrorCode(err)
	}
	if flags.NArg() != 0 {
		return a.unexpectedArguments("list", flags.Args())
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
	format := flags.String("format", "text", "text or json")
	if err := flags.Parse(args); err != nil {
		return flagErrorCode(err)
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
		if *format == "json" {
			output := struct {
				Rule         sdk.Rule `json:"rule"`
				Source       string   `json:"source"`
				PolicyDigest string   `json:"policyDigest"`
			}{Rule: rule, Source: fallback(rule.Pack, "project") + "@" + fallback(rule.PackVersion, "local"), PolicyDigest: sdk.RuleDigest(rule)}
			encoder := json.NewEncoder(a.stdout)
			encoder.SetIndent("", "  ")
			encoder.SetEscapeHTML(false)
			if err := encoder.Encode(output); err != nil {
				return a.fail(err)
			}
			return 0
		}
		if *format != "text" {
			return a.fail(fmt.Errorf("unknown explain format %q", *format))
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

func (a application) completion(args []string) int {
	if len(args) != 1 {
		return a.fail(fmt.Errorf("usage: hoolicy completion bash|zsh|fish"))
	}
	commands := "help version init validate check fix list explain test baseline doctor report fmt lint completion evidence waiver inventory serve migrate pack"
	switch args[0] {
	case "bash":
		fmt.Fprintf(a.stdout, "complete -W %q hoolicy\n", commands)
	case "zsh":
		fmt.Fprintf(a.stdout, "#compdef hoolicy\n_arguments '1:command:(%s)' '*::argument:->args'\n", commands)
	case "fish":
		for _, command := range strings.Fields(commands) {
			fmt.Fprintf(a.stdout, "complete -c hoolicy -f -n '__fish_use_subcommand' -a %s\n", command)
		}
	default:
		return a.fail(fmt.Errorf("unsupported shell %s", args[0]))
	}
	return 0
}

func (a application) evidence(ctx context.Context, args []string) int {
	if len(args) > 0 && args[0] == "verify" {
		return a.evidenceVerify(ctx, args[1:])
	}
	if len(args) > 0 && (args[0] == "help" || args[0] == "-h" || args[0] == "--help") {
		fmt.Fprintln(a.stdout, "Usage: hoolicy evidence [options]\n       hoolicy evidence verify [options] <bundle.json>")
		return 0
	}
	return a.evidenceCreate(ctx, args)
}

func (a application) waiver(ctx context.Context, args []string) int {
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		fmt.Fprintln(a.stdout, "Usage: hoolicy waiver create [options]")
		return 0
	}
	if args[0] != "create" {
		return a.fail(fmt.Errorf("unknown waiver command %s", args[0]))
	}
	flags := flag.NewFlagSet("waiver create", flag.ContinueOnError)
	flags.SetOutput(a.stderr)
	configPath := flags.String("config", "", "configuration path")
	fingerprint := flags.String("fingerprint", "", "exact finding fingerprint")
	id := flags.String("id", "", "waiver ID; defaults from rule and fingerprint")
	owner := flags.String("owner", "", "accountable owner")
	ticket := flags.String("ticket", "", "absolute HTTPS review ticket")
	reason := flags.String("reason", "", "reviewed reason, at least 20 characters")
	approver := flags.String("approver", "", "independent approver")
	expires := flags.String("expires", "", "expiry date in YYYY-MM-DD")
	apply := flags.Bool("apply", false, "write the reviewed waiver")
	if err := flags.Parse(args[1:]); err != nil {
		return flagErrorCode(err)
	}
	if flags.NArg() != 0 {
		return a.unexpectedArguments("waiver create", flags.Args())
	}
	if *fingerprint == "" || *owner == "" || *ticket == "" || *reason == "" || *expires == "" {
		return a.fail(errors.New("--fingerprint, --owner, --ticket, --reason, and --expires are required"))
	}
	project, err := loadProject(*configPath)
	if err != nil {
		return a.fail(err)
	}
	now := time.Now().UTC()
	decision, err := a.engine.Check(ctx, project, engine.Options{Now: now, ToolVersion: a.info.Version})
	if err != nil {
		return a.fail(err)
	}
	var target *sdk.Finding
	for index := range decision.Findings {
		if decision.Findings[index].Fingerprint == *fingerprint && !strings.HasPrefix(decision.Findings[index].RuleID, "hoolicy.") {
			target = &decision.Findings[index]
			break
		}
	}
	if target == nil {
		return a.fail(fmt.Errorf("finding fingerprint %s is not present in current full evaluation", *fingerprint))
	}
	expiry, err := time.Parse("2006-01-02", *expires)
	if err != nil {
		return a.fail(errors.New("--expires must use YYYY-MM-DD"))
	}
	waiverID := *id
	if waiverID == "" {
		waiverID = target.RuleID + "." + target.Fingerprint[:12]
	}
	waiver := config.Waiver{ID: waiverID, Rule: target.RuleID, Fingerprints: []string{target.Fingerprint}, Reason: *reason, Owner: *owner, Ticket: *ticket, Approver: *approver, Created: config.Date{Time: now.UTC().Truncate(24 * time.Hour)}, Expires: config.Date{Time: expiry.UTC()}}
	if err := config.ValidateWaiverForProject(waiver, now, project.RequireWaiverApprover); err != nil {
		return a.fail(err)
	}
	preview, err := yaml.Marshal(config.WaiverFile{Version: config.CurrentVersion, Waivers: []config.Waiver{waiver}})
	if err != nil {
		return a.fail(err)
	}
	fmt.Fprintf(a.stdout, "Waiver preview for %s (%s):\n%s", target.RuleID, target.Location.Path, preview)
	if !*apply {
		fmt.Fprintln(a.stdout, "No files changed. Re-run with --apply after review.")
		return 0
	}
	waiverFile := config.WaiverFile{Version: config.CurrentVersion, Waivers: []config.Waiver{}}
	_, path, pathErr := safepath.Existing(project.Root, project.Waivers)
	if pathErr == nil {
		loaded, err := config.LoadWaivers(path)
		if err != nil {
			return a.fail(err)
		}
		waiverFile = *loaded
	} else if errors.Is(pathErr, os.ErrNotExist) {
		_, path, err = safepath.Writable(project.Root, project.Waivers)
		if err != nil {
			return a.fail(err)
		}
	} else {
		return a.fail(pathErr)
	}
	for _, existing := range waiverFile.Waivers {
		if existing.ID == waiver.ID {
			return a.fail(fmt.Errorf("waiver ID %s already exists", waiver.ID))
		}
	}
	waiverFile.Waivers = append(waiverFile.Waivers, waiver)
	if err := config.SaveWaivers(path, waiverFile); err != nil {
		return a.fail(err)
	}
	fmt.Fprintf(a.stdout, "Applied waiver %s to %s.\n", waiver.ID, filepath.ToSlash(project.Waivers))
	return 0
}

type policyInventory struct {
	Version      int                    `json:"version"`
	Project      string                 `json:"project"`
	Revision     string                 `json:"revision"`
	GeneratedAt  time.Time              `json:"generatedAt"`
	PolicyDigest string                 `json:"policyDigest"`
	Scopes       []inventoryScope       `json:"scopes"`
	Waivers      []config.Waiver        `json:"waivers"`
	Budgets      config.ResourceBudgets `json:"budgets"`
}

type inventoryScope struct {
	Name       string          `json:"name"`
	Owner      string          `json:"owner"`
	Paths      []string        `json:"paths"`
	Packs      []string        `json:"packs"`
	Parameters map[string]any  `json:"parameters"`
	DependsOn  []string        `json:"dependsOn"`
	Rules      []inventoryRule `json:"rules"`
}

type inventoryRule struct {
	ID          string        `json:"id"`
	Kind        string        `json:"kind"`
	Severity    sdk.Severity  `json:"severity"`
	Digest      string        `json:"digest"`
	Pack        string        `json:"pack,omitempty"`
	PackVersion string        `json:"packVersion,omitempty"`
	Controls    []sdk.Control `json:"controls"`
}

func (a application) inventory(ctx context.Context, args []string) int {
	flags := flag.NewFlagSet("inventory", flag.ContinueOnError)
	flags.SetOutput(a.stderr)
	configPath := flags.String("config", "", "configuration path")
	output := flags.String("output", "", "write JSON inventory to file")
	if err := flags.Parse(args); err != nil {
		return flagErrorCode(err)
	}
	if flags.NArg() != 0 {
		return a.unexpectedArguments("inventory", flags.Args())
	}
	project, err := loadProject(*configPath)
	if err != nil {
		return a.fail(err)
	}
	inventory, err := a.buildInventory(ctx, project)
	if err != nil {
		return a.fail(err)
	}
	data, err := json.MarshalIndent(inventory, "", "  ")
	if err != nil {
		return a.fail(err)
	}
	data = append(data, '\n')
	if *output != "" {
		if err := writeReportFile(*output, data); err != nil {
			return a.fail(err)
		}
	} else {
		_, _ = a.stdout.Write(data)
	}
	return 0
}

func (a application) buildInventory(ctx context.Context, project *config.Project) (*policyInventory, error) {
	rules, err := a.engine.Validate(project)
	if err != nil {
		return nil, err
	}
	decision, err := a.engine.Check(ctx, project, engine.Options{ToolVersion: a.info.Version})
	if err != nil {
		return nil, err
	}
	toRule := func(rule sdk.Rule) inventoryRule {
		controls := append([]sdk.Control(nil), rule.Controls...)
		if controls == nil {
			controls = []sdk.Control{}
		}
		return inventoryRule{ID: rule.ID, Kind: rule.Kind, Severity: rule.Severity, Digest: sdk.RuleDigest(rule), Pack: rule.Pack, PackVersion: rule.PackVersion, Controls: controls}
	}
	scopes := []inventoryScope{}
	if len(project.Workspaces) == 0 {
		items := make([]inventoryRule, 0, len(rules))
		packs := []string{}
		for _, reference := range project.Packs {
			packs = append(packs, reference.Name)
		}
		for _, rule := range rules {
			items = append(items, toRule(rule))
		}
		scopes = append(scopes, inventoryScope{Name: "root", Owner: "repository", Paths: []string{"**/*"}, Packs: packs, Parameters: project.Parameters, DependsOn: []string{}, Rules: items})
	} else {
		global := inventoryScope{Name: "root", Owner: "repository", Paths: []string{"**/*"}, Packs: []string{}, Parameters: project.Parameters, DependsOn: []string{}, Rules: []inventoryRule{}}
		for _, rule := range rules {
			if rule.Pack == "" {
				global.Rules = append(global.Rules, toRule(rule))
			}
		}
		scopes = append(scopes, global)
		for _, workspace := range project.Workspaces {
			parameters := map[string]any{}
			for key, value := range project.Parameters {
				parameters[key] = value
			}
			byName := map[string]config.Workspace{}
			for _, candidate := range project.Workspaces {
				byName[candidate.Name] = candidate
			}
			visited := map[string]bool{}
			var mergeDependency func(string)
			mergeDependency = func(name string) {
				if visited[name] {
					return
				}
				visited[name] = true
				candidate := byName[name]
				for _, nested := range candidate.DependsOn {
					mergeDependency(nested)
				}
				for key, value := range candidate.Parameters {
					parameters[key] = value
				}
			}
			for _, dependency := range workspace.DependsOn {
				mergeDependency(dependency)
			}
			for key, value := range workspace.Parameters {
				parameters[key] = value
			}
			selected := map[string]bool{}
			for _, name := range workspace.Packs {
				selected[name] = true
			}
			items := []inventoryRule{}
			for _, rule := range rules {
				if rule.Pack != "" && selected[rule.Pack] {
					items = append(items, toRule(rule))
				}
			}
			scopes = append(scopes, inventoryScope{Name: workspace.Name, Owner: workspace.Owner, Paths: append([]string(nil), workspace.Paths...), Packs: append([]string(nil), workspace.Packs...), Parameters: parameters, DependsOn: append([]string(nil), workspace.DependsOn...), Rules: items})
		}
	}
	return &policyInventory{Version: 1, Project: project.Project, Revision: decision.Git.Commit, GeneratedAt: decision.GeneratedAt, PolicyDigest: decision.PolicyDigest, Scopes: scopes, Waivers: append([]config.Waiver{}, decision.Waivers...), Budgets: project.Budgets}, nil
}

func (a application) serve(ctx context.Context, args []string) int {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	flags.SetOutput(a.stderr)
	configPath := flags.String("config", "", "configuration path")
	listen := flags.String("listen", "127.0.0.1:8941", "loopback listen address")
	if err := flags.Parse(args); err != nil {
		return flagErrorCode(err)
	}
	if flags.NArg() != 0 {
		return a.unexpectedArguments("serve", flags.Args())
	}
	host, _, err := net.SplitHostPort(*listen)
	if err != nil {
		return a.fail(fmt.Errorf("invalid --listen: %w", err))
	}
	address := net.ParseIP(host)
	if address == nil || !address.IsLoopback() {
		return a.fail(errors.New("serve only accepts an explicit numeric loopback address"))
	}
	project, err := loadProject(*configPath)
	if err != nil {
		return a.fail(err)
	}
	server := &http.Server{Addr: *listen, Handler: a.readOnlyHandler(project.Path), ReadHeaderTimeout: 5 * time.Second, WriteTimeout: 5 * time.Minute, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	shutdownDone := make(chan struct{})
	defer close(shutdownDone)
	go func() {
		select {
		case <-ctx.Done():
			shutdownContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer cancel()
			_ = server.Shutdown(shutdownContext)
		case <-shutdownDone:
		}
	}()
	fmt.Fprintf(a.stdout, "Hoolicy read-only service listening on http://%s.\n", *listen)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return a.fail(err)
	}
	return 0
}

func (a application) readOnlyHandler(configPath string) http.Handler {
	mux := http.NewServeMux()
	jsonError := func(writer http.ResponseWriter, status int, err error) {
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(status)
		_ = json.NewEncoder(writer).Encode(map[string]string{"error": err.Error()})
	}
	getOnly := func(handler func(*http.Request) (any, error)) http.HandlerFunc {
		return func(writer http.ResponseWriter, request *http.Request) {
			if request.Method != http.MethodGet {
				jsonError(writer, http.StatusMethodNotAllowed, errors.New("read-only service accepts GET only"))
				return
			}
			payload, err := handler(request)
			if err != nil {
				jsonError(writer, http.StatusInternalServerError, err)
				return
			}
			data, err := json.Marshal(payload)
			if err != nil {
				jsonError(writer, http.StatusInternalServerError, fmt.Errorf("encode response: %w", err))
				return
			}
			writer.Header().Set("Content-Type", "application/json")
			_, _ = writer.Write(append(data, '\n'))
		}
	}
	mux.HandleFunc("/health", getOnly(func(_ *http.Request) (any, error) {
		return map[string]string{"status": "ok"}, nil
	}))
	mux.HandleFunc("/v1/check", getOnly(func(request *http.Request) (any, error) {
		project, err := config.LoadProject(configPath)
		if err != nil {
			return nil, err
		}
		decision, err := a.engine.Check(request.Context(), project, engine.Options{ToolVersion: a.info.Version})
		if err != nil {
			return nil, err
		}
		return decision, nil
	}))
	mux.HandleFunc("/v1/inventory", getOnly(func(request *http.Request) (any, error) {
		project, err := config.LoadProject(configPath)
		if err != nil {
			return nil, err
		}
		inventory, err := a.buildInventory(request.Context(), project)
		if err != nil {
			return nil, err
		}
		return inventory, nil
	}))
	return mux
}

func (a application) migrate(args []string) int {
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		fmt.Fprintln(a.stdout, "Usage: hoolicy migrate report [--output path] [--apply] <report.json>")
		return 0
	}
	if args[0] != "report" {
		return a.fail(fmt.Errorf("unsupported migration kind %s", args[0]))
	}
	flags := flag.NewFlagSet("migrate report", flag.ContinueOnError)
	flags.SetOutput(a.stderr)
	output := flags.String("output", "", "migration target; defaults to input")
	apply := flags.Bool("apply", false, "write the reviewed migration")
	if err := flags.Parse(args[1:]); err != nil {
		return flagErrorCode(err)
	}
	if flags.NArg() != 1 {
		return a.fail(errors.New("usage: hoolicy migrate report [--output path] [--apply] <report.json>"))
	}
	inputPath := flags.Arg(0)
	input, err := report.LoadJSON(inputPath)
	if err != nil {
		return a.fail(err)
	}
	if input.ReportVersion == 2 {
		fmt.Fprintln(a.stdout, "Report already uses current version 2. No migration needed.")
		return 0
	}
	before := input.ReportVersion
	input.ReportVersion = 2
	if input.PolicyDigest == "" {
		input.PolicyDigest = input.ConfigDigest
	}
	if input.Findings == nil {
		input.Findings = []sdk.Finding{}
	}
	if input.Waivers == nil {
		input.Waivers = []config.Waiver{}
	}
	if input.Metrics.Rules == nil {
		input.Metrics.Rules = []engine.RuleMetric{}
	}
	var encoded bytes.Buffer
	if err := report.Write(&encoded, "json", input, false); err != nil {
		return a.fail(err)
	}
	fmt.Fprintf(a.stdout, "Migration preview: report version %d to 2.\n", before)
	if !*apply {
		_, _ = a.stdout.Write(encoded.Bytes())
		fmt.Fprintln(a.stdout, "No files changed. Re-run with --apply after review.")
		return 0
	}
	target := *output
	if target == "" {
		target = inputPath
	}
	if err := writeReportFile(target, encoded.Bytes()); err != nil {
		return a.fail(err)
	}
	fmt.Fprintf(a.stdout, "Migrated report to version 2 at %s.\n", target)
	return 0
}

func (a application) evidenceCreate(ctx context.Context, args []string) int {
	flags := flag.NewFlagSet("evidence", flag.ContinueOnError)
	flags.SetOutput(a.stderr)
	configPath := flags.String("config", "", "configuration path")
	output := flags.String("output", "hoolicy-evidence.json", "evidence bundle output")
	base := flags.String("base", envFirst("HOOLICY_BASE_SHA", "CI_MERGE_REQUEST_DIFF_BASE_SHA"), "base revision")
	attestation := flags.String("attestation", "", "optional in-toto statement output")
	signatureBundle := flags.String("signature-bundle", "", "Sigstore verification bundle output")
	signKey := flags.String("sign-key", "", "Cosign private key or KMS URI")
	keyless := flags.Bool("keyless", false, "use ambient keyless Sigstore identity")
	if err := flags.Parse(args); err != nil {
		return flagErrorCode(err)
	}
	if flags.NArg() != 0 {
		return a.unexpectedArguments("evidence", flags.Args())
	}
	if *attestation == "" && (*signatureBundle != "" || *signKey != "" || *keyless) {
		return a.fail(errors.New("signing options require --attestation"))
	}
	if *attestation != "" && (*signatureBundle == "" || ((*signKey == "") == !*keyless)) {
		return a.fail(errors.New("attestation requires --signature-bundle and exactly one --sign-key or --keyless"))
	}
	project, err := loadProject(*configPath)
	if err != nil {
		return a.fail(err)
	}
	rules, err := a.engine.Validate(project)
	if err != nil {
		return a.fail(err)
	}
	decision, err := a.engine.Check(ctx, project, engine.Options{BaseSHA: *base, ToolVersion: a.info.Version})
	if err != nil {
		return a.fail(err)
	}
	bundle, err := evidence.Build(project, decision, rules)
	if err != nil {
		return a.fail(err)
	}
	data, err := evidence.Marshal(bundle)
	if err != nil {
		return a.fail(err)
	}
	if err := writeReportFile(*output, data); err != nil {
		return a.fail(err)
	}
	if *attestation != "" {
		if err := createDecisionAttestation(*attestation, *signatureBundle, *signKey, *keyless, bundle, data); err != nil {
			return a.fail(err)
		}
	}
	fmt.Fprintf(a.stdout, "Wrote verifiable evidence for %d rules, %d external artifacts, and %d controls to %s.\n", len(bundle.Rules), len(bundle.External), len(bundle.Controls), *output)
	if decision.Summary.Blocking > 0 {
		return 1
	}
	return 0
}

type decisionStatement struct {
	Type          string             `json:"_type"`
	Subject       []statementSubject `json:"subject"`
	PredicateType string             `json:"predicateType"`
	Predicate     statementPredicate `json:"predicate"`
}
type statementSubject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}
type statementPredicate struct {
	Project        string         `json:"project"`
	Revision       string         `json:"revision"`
	PolicyDigest   string         `json:"policyDigest"`
	EvidenceDigest string         `json:"evidenceDigest"`
	Decision       engine.Summary `json:"decision"`
}

func createDecisionAttestation(path, bundlePath, key string, keyless bool, bundle *evidence.Bundle, evidenceData []byte) error {
	statement := decisionStatement{Type: "https://in-toto.io/Statement/v1", Subject: []statementSubject{{Name: bundle.Project, Digest: map[string]string{"gitCommit": bundle.Revision}}, {Name: "hoolicy-evidence.json", Digest: map[string]string{"sha256": strings.TrimPrefix(sha256Digest(evidenceData), "sha256:")}}}, PredicateType: "https://openhoo.dev/hoolicy/decision/v1", Predicate: statementPredicate{Project: bundle.Project, Revision: bundle.Revision, PolicyDigest: bundle.PolicyDigest, EvidenceDigest: sha256Digest(evidenceData), Decision: bundle.Decision.Summary}}
	data, err := json.MarshalIndent(statement, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	statementTemporary, err := stageReportFile(path, data)
	if err != nil {
		return err
	}
	defer os.Remove(statementTemporary)
	bundleTemporary, err := reserveReportPath(bundlePath)
	if err != nil {
		return err
	}
	defer os.Remove(bundleTemporary)
	args := []string{"sign-blob", "--yes", "--bundle", bundleTemporary}
	if key != "" {
		args = append(args, "--key", key)
	}
	args = append(args, "--", statementTemporary)
	if output, err := exec.Command("cosign", args...).CombinedOutput(); err != nil {
		return fmt.Errorf("cosign sign-blob: %s", commandOutputLine(output))
	}
	bundleData, err := os.ReadFile(bundleTemporary)
	if err != nil || len(bundleData) == 0 {
		return errors.New("cosign produced no signature bundle")
	}
	if err := writeReportFile(bundlePath, bundleData); err != nil {
		return err
	}
	if err := writeReportFile(path, data); err != nil {
		return err
	}
	return nil
}

func (a application) evidenceVerify(ctx context.Context, args []string) int {
	flags := flag.NewFlagSet("evidence verify", flag.ContinueOnError)
	flags.SetOutput(a.stderr)
	configPath := flags.String("config", "", "configuration path")
	attestation := flags.String("attestation", "", "in-toto statement to verify")
	signatureBundle := flags.String("signature-bundle", "", "Sigstore bundle")
	key := flags.String("key", "", "Cosign public key or KMS URI")
	identity := flags.String("identity", "", "expected keyless certificate identity")
	issuer := flags.String("issuer", "", "expected keyless OIDC issuer")
	if err := flags.Parse(args); err != nil {
		return flagErrorCode(err)
	}
	if flags.NArg() != 1 {
		return a.fail(errors.New("usage: hoolicy evidence verify [options] <bundle.json>"))
	}
	bundlePath := flags.Arg(0)
	bundle, err := evidence.Load(bundlePath)
	if err != nil {
		return a.fail(err)
	}
	project, err := loadProject(*configPath)
	if err != nil {
		return a.fail(err)
	}
	rules, err := a.engine.Validate(project)
	if err != nil {
		return a.fail(err)
	}
	base := ""
	if bundle.Decision != nil && bundle.Decision.Comparison != nil {
		base = bundle.Decision.Comparison.BaseRevision
	}
	current, err := a.engine.Check(ctx, project, engine.Options{Now: bundle.CreatedAt, BaseSHA: base, ToolVersion: bundle.Tool.Version})
	if err != nil {
		return a.fail(err)
	}
	if err := evidence.Verify(project, bundle, current, rules, time.Now().UTC()); err != nil {
		return a.fail(err)
	}
	if *attestation == "" && (*signatureBundle != "" || *key != "" || *identity != "" || *issuer != "") {
		return a.fail(errors.New("signature verification options require --attestation"))
	}
	if *attestation != "" {
		if *signatureBundle == "" {
			return a.fail(errors.New("attestation verification requires --signature-bundle"))
		}
		if (*key == "") == (*identity == "" && *issuer == "") {
			return a.fail(errors.New("use exactly one --key or --identity plus --issuer"))
		}
		if *key == "" && (*identity == "" || *issuer == "") {
			return a.fail(errors.New("both --identity and --issuer are required"))
		}
		if err := verifyDecisionAttestation(bundle, bundlePath, *attestation, *signatureBundle, *key, *identity, *issuer); err != nil {
			return a.fail(err)
		}
	}
	fmt.Fprintf(a.stdout, "Verified evidence bundle for %s at %s with %d external artifacts.\n", bundle.Project, bundle.Revision, len(bundle.External))
	return 0
}

func verifyDecisionAttestation(bundle *evidence.Bundle, evidencePath, attestation, bundlePath, key, identity, issuer string) error {
	evidenceData, err := os.ReadFile(evidencePath)
	if err != nil {
		return err
	}
	statementData, err := os.ReadFile(attestation)
	if err != nil {
		return err
	}
	var statement decisionStatement
	decoder := json.NewDecoder(bytes.NewReader(statementData))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&statement); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("exactly one attestation JSON value is required")
		}
		return err
	}
	if statement.Type != "https://in-toto.io/Statement/v1" || statement.PredicateType != "https://openhoo.dev/hoolicy/decision/v1" || statement.Predicate.EvidenceDigest != sha256Digest(evidenceData) || statement.Predicate.Project != bundle.Project || statement.Predicate.Revision != bundle.Revision || statement.Predicate.PolicyDigest != bundle.PolicyDigest || statement.Predicate.Decision != bundle.Decision.Summary {
		return errors.New("attestation does not bind this evidence bundle")
	}
	expectedSubjects := map[string]string{bundle.Project: bundle.Revision, "hoolicy-evidence.json": strings.TrimPrefix(sha256Digest(evidenceData), "sha256:")}
	if len(statement.Subject) != len(expectedSubjects) {
		return errors.New("attestation subjects do not bind this evidence bundle")
	}
	for _, subject := range statement.Subject {
		expected, exists := expectedSubjects[subject.Name]
		if !exists {
			return errors.New("attestation subjects do not bind this evidence bundle")
		}
		actual := subject.Digest["sha256"]
		if subject.Name == bundle.Project {
			actual = subject.Digest["gitCommit"]
		}
		if actual != expected {
			return errors.New("attestation subjects do not bind this evidence bundle")
		}
		delete(expectedSubjects, subject.Name)
	}
	if len(expectedSubjects) != 0 {
		return errors.New("attestation subjects do not bind this evidence bundle")
	}
	args := []string{"verify-blob", "--bundle", bundlePath}
	if key != "" {
		args = append(args, "--key", key)
	} else {
		args = append(args, "--certificate-identity", identity, "--certificate-oidc-issuer", issuer)
	}
	args = append(args, "--", attestation)
	if output, err := exec.Command("cosign", args...).CombinedOutput(); err != nil {
		return fmt.Errorf("cosign verify-blob: %s", commandOutputLine(output))
	}
	return nil
}

func (a application) test(ctx context.Context, args []string) int {
	flags := flag.NewFlagSet("test", flag.ContinueOnError)
	flags.SetOutput(a.stderr)
	if err := flags.Parse(args); err != nil {
		return flagErrorCode(err)
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

func (a application) baseline(ctx context.Context, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(a.stderr, "usage: hoolicy baseline create|prune")
		return 2
	}
	switch args[0] {
	case "help", "-h", "--help":
		fmt.Fprintln(a.stdout, "Usage: hoolicy baseline create|prune")
		return 0
	case "create":
		return a.baselineCreate(ctx, args[1:])
	case "prune":
		return a.baselinePrune(ctx, args[1:])
	default:
		return a.fail(fmt.Errorf("unknown baseline command %s", args[0]))
	}
}

func (a application) baselineCreate(ctx context.Context, args []string) int {
	flags := flag.NewFlagSet("baseline create", flag.ContinueOnError)
	flags.SetOutput(a.stderr)
	configPath := flags.String("config", "", "configuration path")
	apply := flags.Bool("apply", false, "write the exact previewed baseline")
	replace := flags.Bool("replace", false, "replace an existing baseline")
	if err := flags.Parse(args); err != nil {
		return flagErrorCode(err)
	}
	if flags.NArg() != 0 {
		return a.unexpectedArguments("baseline create", flags.Args())
	}
	project, err := loadProject(*configPath)
	if err != nil {
		return a.fail(err)
	}
	_, path, err := safepath.Writable(project.Root, project.Baseline)
	if err != nil {
		return a.fail(fmt.Errorf("unsafe baseline path: %w", err))
	}
	if _, err := os.Lstat(path); err == nil && !*replace {
		return a.fail(fmt.Errorf("%s already exists; use baseline prune or --replace", project.Baseline))
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return a.fail(err)
	}
	result, err := a.engine.Check(ctx, project, engine.Options{ToolVersion: a.info.Version})
	if err != nil {
		return a.fail(err)
	}
	baseline := config.BaselineFile{
		Version: config.CurrentVersion, Project: project.Project, CreatedAt: result.GeneratedAt.UTC().Truncate(time.Second),
		ToolVersion: a.info.Version, Revision: result.Git.Commit, PolicyDigest: result.PolicyDigest, Entries: make([]config.BaselineEntry, 0),
	}
	for _, finding := range result.Findings {
		if finding.Waived || strings.HasPrefix(finding.RuleID, "hoolicy.") {
			continue
		}
		baseline.Entries = append(baseline.Entries, config.BaselineEntry{
			Fingerprint: finding.Fingerprint, RuleID: finding.RuleID, Severity: finding.Severity,
			PolicyDigest: finding.PolicyDigest, FindingDigest: finding.FindingDigest, CreatedAt: baseline.CreatedAt,
		})
	}
	data, err := baselineJSON(baseline)
	if err != nil {
		return a.fail(err)
	}
	fmt.Fprint(a.stdout, string(data))
	if !*apply {
		fmt.Fprintln(a.stdout, "Preview only. Re-run with --apply after reviewing this baseline.")
		return 0
	}
	if err := config.SaveBaseline(path, baseline); err != nil {
		return a.fail(err)
	}
	fmt.Fprintf(a.stdout, "Wrote %d reviewed findings to %s.\n", len(baseline.Entries), project.Baseline)
	return 0
}

func (a application) baselinePrune(ctx context.Context, args []string) int {
	flags := flag.NewFlagSet("baseline prune", flag.ContinueOnError)
	flags.SetOutput(a.stderr)
	configPath := flags.String("config", "", "configuration path")
	apply := flags.Bool("apply", false, "write the exact previewed pruned baseline")
	if err := flags.Parse(args); err != nil {
		return flagErrorCode(err)
	}
	if flags.NArg() != 0 {
		return a.unexpectedArguments("baseline prune", flags.Args())
	}
	project, err := loadProject(*configPath)
	if err != nil {
		return a.fail(err)
	}
	_, path, err := safepath.Existing(project.Root, project.Baseline)
	if err != nil {
		return a.fail(err)
	}
	baseline, err := config.LoadBaseline(path)
	if err != nil {
		return a.fail(err)
	}
	result, err := a.engine.Check(ctx, project, engine.Options{ToolVersion: a.info.Version})
	if err != nil {
		return a.fail(err)
	}
	current := make(map[string]sdk.Finding, len(result.Findings))
	for _, finding := range result.Findings {
		current[finding.Fingerprint] = finding
	}
	pruned := *baseline
	pruned.PolicyDigest = result.PolicyDigest
	pruned.Entries = nil
	for _, entry := range baseline.Entries {
		finding, exists := current[entry.Fingerprint]
		if exists && entry.RuleID == finding.RuleID && entry.Severity == finding.Severity && entry.PolicyDigest == finding.PolicyDigest && entry.FindingDigest == finding.FindingDigest {
			pruned.Entries = append(pruned.Entries, entry)
		}
	}
	data, err := baselineJSON(pruned)
	if err != nil {
		return a.fail(err)
	}
	for _, change := range result.Changes {
		if change.Source == "baseline" {
			fmt.Fprintf(a.stdout, "- %s %s %s: %s\n", change.RuleID, short(change.Fingerprint), change.State, change.Reason)
		}
	}
	fmt.Fprint(a.stdout, string(data))
	if !*apply {
		fmt.Fprintln(a.stdout, "Preview only. Re-run with --apply after reviewing this prune.")
		return 0
	}
	if err := config.SaveBaseline(path, pruned); err != nil {
		return a.fail(err)
	}
	fmt.Fprintf(a.stdout, "Pruned %d entries from %s; %d remain.\n", len(baseline.Entries)-len(pruned.Entries), project.Baseline, len(pruned.Entries))
	return 0
}

func baselineJSON(baseline config.BaselineFile) ([]byte, error) {
	sort.Slice(baseline.Entries, func(i, j int) bool {
		if baseline.Entries[i].RuleID != baseline.Entries[j].RuleID {
			return baseline.Entries[i].RuleID < baseline.Entries[j].RuleID
		}
		return baseline.Entries[i].Fingerprint < baseline.Entries[j].Fingerprint
	})
	if err := config.ValidateBaseline(baseline); err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(baseline, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func short(value string) string {
	if len(value) > 12 {
		return value[:12]
	}
	return value
}

func (a application) doctor(ctx context.Context, args []string) int {
	flags := flag.NewFlagSet("doctor", flag.ContinueOnError)
	flags.SetOutput(a.stderr)
	configPath := flags.String("config", "", "configuration path")
	base := flags.String("base", envFirst("HOOLICY_BASE_SHA", "CI_MERGE_REQUEST_DIFF_BASE_SHA"), "base revision expected in CI")
	if err := flags.Parse(args); err != nil {
		return flagErrorCode(err)
	}
	if flags.NArg() != 0 {
		return a.unexpectedArguments("doctor", flags.Args())
	}
	path, err := config.Find(".", *configPath)
	if err != nil {
		return a.fail(fmt.Errorf("config discovery: %w", err))
	}
	fmt.Fprintf(a.stdout, "OK config-discovery %s\n", path)
	project, err := config.LoadProject(path)
	if err != nil {
		return a.fail(fmt.Errorf("configuration: %w", err))
	}
	rules, err := a.engine.Validate(project)
	if err != nil {
		return a.fail(fmt.Errorf("packs and compatibility: %w", err))
	}
	fmt.Fprintf(a.stdout, "OK packs-and-compatibility %d active rules; lock integrity verified\n", len(rules))
	repo, err := repository.Open(project.Root, repository.Options{BaseSHA: *base})
	if err != nil {
		return a.fail(fmt.Errorf("git context: %w", err))
	}
	git := repo.Git()
	if git.Commit == "" {
		fmt.Fprintln(a.stdout, "WARN git-context no Git commit detected")
	} else {
		fmt.Fprintf(a.stdout, "OK git-context %s dirty=%t\n", short(git.Commit), git.Dirty)
	}
	warnings := 0
	if (*base == "") && (os.Getenv("GITHUB_EVENT_NAME") == "pull_request" || os.Getenv("CI_MERGE_REQUEST_IID") != "") {
		warnings++
		fmt.Fprintln(a.stdout, "WARN ci-base-revision missing; set HOOLICY_BASE_SHA and fetch full base history")
	} else if *base != "" {
		if _, err := repository.OpenRevision(project.Root, *base, repository.Options{}); err != nil {
			return a.fail(fmt.Errorf("CI base revision: %w", err))
		}
		fmt.Fprintf(a.stdout, "OK ci-base-revision %s\n", *base)
	} else {
		fmt.Fprintln(a.stdout, "OK ci-base-revision not required outside pull or merge request")
	}
	ignored, err := repository.IgnoredFiles(project.Root)
	if err != nil {
		return a.fail(err)
	}
	ignoredTargets := make(map[string][]string)
	for _, ignoredPath := range ignored {
		for _, rule := range rules {
			if len(rule.Files) == 0 {
				continue
			}
			matched, matchErr := repository.Matches(ignoredPath, rule.Files)
			if matchErr != nil {
				return a.fail(matchErr)
			}
			excluded, matchErr := repository.Matches(ignoredPath, rule.Exclude)
			if matchErr != nil {
				return a.fail(matchErr)
			}
			if matched && !excluded {
				ignoredTargets[ignoredPath] = append(ignoredTargets[ignoredPath], rule.ID)
			}
		}
	}
	if len(ignoredTargets) == 0 {
		fmt.Fprintln(a.stdout, "OK ignored-targets no ignored files match active rule scopes")
	} else {
		warnings++
		paths := make([]string, 0, len(ignoredTargets))
		for path := range ignoredTargets {
			paths = append(paths, path)
		}
		sort.Strings(paths)
		for _, path := range paths {
			sort.Strings(ignoredTargets[path])
			fmt.Fprintf(a.stdout, "WARN ignored-target %s matches %s\n", path, strings.Join(ignoredTargets[path], ","))
		}
	}
	if _, err := a.engine.Check(ctx, project, engine.Options{BaseSHA: *base, ToolVersion: a.info.Version}); err != nil {
		if strings.Contains(err.Error(), "unsupported document format") {
			return a.fail(fmt.Errorf("unsupported file types: %w", err))
		}
		return a.fail(fmt.Errorf("policy execution readiness: %w", err))
	}
	fmt.Fprintln(a.stdout, "OK unsupported-types all matched structured inputs parsed successfully")
	if warnings > 0 {
		return 1
	}
	return 0
}

func (a application) report(args []string) int {
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		fmt.Fprintln(a.stdout, "Usage: hoolicy report diff [--format text|json] <before.json> <after.json>")
		return 0
	}
	if args[0] != "diff" {
		return a.fail(fmt.Errorf("unknown report command %s", args[0]))
	}
	flags := flag.NewFlagSet("report diff", flag.ContinueOnError)
	flags.SetOutput(a.stderr)
	format := flags.String("format", "text", "text or json")
	if err := flags.Parse(args[1:]); err != nil {
		return flagErrorCode(err)
	}
	if flags.NArg() != 2 {
		return a.fail(fmt.Errorf("usage: hoolicy report diff [--format text|json] <before.json> <after.json>"))
	}
	before, err := report.LoadJSON(flags.Arg(0))
	if err != nil {
		return a.fail(err)
	}
	after, err := report.LoadJSON(flags.Arg(1))
	if err != nil {
		return a.fail(err)
	}
	if err := report.WriteDiff(a.stdout, *format, report.Compare(before, after)); err != nil {
		return a.fail(err)
	}
	return 0
}

func (a application) format(args []string) int {
	flags := flag.NewFlagSet("fmt", flag.ContinueOnError)
	flags.SetOutput(a.stderr)
	check := flags.Bool("check", false, "report files that need formatting without writing")
	if err := flags.Parse(args); err != nil {
		return flagErrorCode(err)
	}
	paths := flags.Args()
	if len(paths) == 0 {
		path, err := config.Find(".", "")
		if err != nil {
			return a.fail(err)
		}
		paths = []string{path}
	}
	changed := 0
	for _, path := range paths {
		data, err := formattedYAML(path)
		if err != nil {
			return a.fail(err)
		}
		current, err := os.ReadFile(path)
		if err != nil {
			return a.fail(err)
		}
		if bytes.Equal(current, data) {
			continue
		}
		changed++
		fmt.Fprintln(a.stdout, filepath.ToSlash(path))
		if !*check {
			if err := writeReportFile(path, data); err != nil {
				return a.fail(err)
			}
		}
	}
	if *check && changed > 0 {
		return 1
	}
	return 0
}

func formattedYAML(path string) ([]byte, error) {
	var value any
	switch filepath.Base(path) {
	case config.DefaultFilename:
		loaded, err := config.LoadProject(path)
		if err != nil {
			return nil, err
		}
		value = loaded
	case "pack.yaml":
		loaded, err := config.LoadPack(path)
		if err != nil {
			return nil, err
		}
		value = loaded
	case "cases.yaml":
		var loaded policytest.File
		if err := config.LoadYAMLStrict(path, &loaded); err != nil {
			return nil, err
		}
		value = loaded
	case "waivers.yaml":
		loaded, err := config.LoadWaivers(path)
		if err != nil {
			return nil, err
		}
		value = loaded
	default:
		return nil, fmt.Errorf("%s is not a Hoolicy-owned YAML file", path)
	}
	data, err := yaml.Marshal(value)
	if err != nil {
		return nil, err
	}
	return data, nil
}

type stringListFlag []string

func (values *stringListFlag) String() string { return strings.Join(*values, ",") }
func (values *stringListFlag) Set(value string) error {
	if strings.TrimSpace(value) == "" || !strings.Contains(value, ":") {
		return fmt.Errorf("disable must be check:scope")
	}
	*values = append(*values, value)
	return nil
}

func (a application) lint(args []string) int {
	flags := flag.NewFlagSet("lint", flag.ContinueOnError)
	flags.SetOutput(a.stderr)
	format := flags.String("format", "text", "text or json")
	previousPath := flags.String("previous", "", "previous pack for severity compatibility checks")
	var disabled stringListFlag
	flags.Var(&disabled, "disable", "narrow heuristic suppression as check:rule-or-parameter")
	if err := flags.Parse(args); err != nil {
		return flagErrorCode(err)
	}
	paths := flags.Args()
	if len(paths) == 0 {
		paths = []string{"."}
	}
	var previous *config.Pack
	var err error
	if *previousPath != "" {
		previous, err = config.LoadPack(*previousPath)
		if err != nil {
			return a.fail(err)
		}
	}
	all := make(map[string][]policylint.Finding)
	total := 0
	for _, path := range paths {
		pack, err := config.LoadPack(path)
		if err != nil {
			return a.fail(err)
		}
		if previous != nil && previous.Name != pack.Name {
			return a.fail(fmt.Errorf("previous pack %s does not match %s", previous.Name, pack.Name))
		}
		findings := policylint.Pack(pack, previous, disabled)
		all[filepath.ToSlash(path)] = findings
		total += len(findings)
	}
	if *format == "json" {
		data, _ := json.MarshalIndent(all, "", "  ")
		fmt.Fprintln(a.stdout, string(data))
	} else if *format == "text" {
		keys := make([]string, 0, len(all))
		for key := range all {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, path := range keys {
			for _, finding := range all[path] {
				fmt.Fprintf(a.stdout, "LINT %s %s %s: %s\n  Heuristic: %s\n  Fix: %s\n", finding.Check, finding.Scope, path, finding.Message, finding.Heuristic, finding.Remediation)
			}
		}
		fmt.Fprintf(a.stdout, "\n%d lint findings. Suppress narrowly with --disable check:scope after review.\n", total)
	} else {
		return a.fail(fmt.Errorf("unknown lint format %q", *format))
	}
	if total > 0 {
		return 1
	}
	return 0
}

func (a application) pack(ctx context.Context, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(a.stderr, "usage: hoolicy pack init|add|update|verify|snapshot|compare|publish|catalog")
		return 2
	}
	switch args[0] {
	case "help", "-h", "--help":
		fmt.Fprintln(a.stdout, "Usage: hoolicy pack init|add|update|verify|snapshot|compare|publish|catalog")
		return 0
	case "init":
		return a.packInit(ctx, args[1:])
	case "add":
		return a.packAdd(args[1:])
	case "update":
		return a.packUpdate(args[1:])
	case "verify":
		return a.packVerify(ctx, args[1:])
	case "snapshot":
		return a.packSnapshot(ctx, args[1:])
	case "compare":
		return a.packCompare(ctx, args[1:])
	case "publish":
		return a.packPublish(ctx, args[1:])
	case "catalog":
		return a.packCatalog(args[1:])
	default:
		return a.fail(fmt.Errorf("unknown pack command %s", args[0]))
	}
}

func (a application) packCatalog(args []string) int {
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		fmt.Fprintln(a.stdout, "Usage: hoolicy pack catalog publish|pull|verify|resolve")
		return 0
	}
	switch args[0] {
	case "publish":
		return a.packCatalogPublish(args[1:])
	case "pull":
		return a.packCatalogPull(args[1:])
	case "verify":
		return a.packCatalogVerify(args[1:])
	case "resolve":
		return a.packCatalogResolve(args[1:])
	default:
		return a.fail(fmt.Errorf("unknown catalog command %s", args[0]))
	}
}

func (a application) packCatalogPublish(args []string) int {
	flags := flag.NewFlagSet("pack catalog publish", flag.ContinueOnError)
	flags.SetOutput(a.stderr)
	reference := flags.String("reference", "", "OCI registry reference with explicit tag")
	signKey := flags.String("sign-key", "", "Cosign private key or KMS URI")
	keyless := flags.Bool("keyless", false, "use ambient keyless Sigstore identity")
	if err := flags.Parse(args); err != nil {
		return flagErrorCode(err)
	}
	if flags.NArg() != 1 || *reference == "" {
		return a.fail(errors.New("usage: hoolicy pack catalog publish --reference registry/repo:tag (--sign-key key|--keyless) <catalog.json>"))
	}
	if (*signKey == "") == !*keyless {
		return a.fail(errors.New("exactly one --sign-key or --keyless is required"))
	}
	if err := config.ValidateOCIReference(*reference); err != nil {
		return a.fail(err)
	}
	catalog, err := config.LoadCatalog(flags.Arg(0))
	if err != nil {
		return a.fail(err)
	}
	data, err := os.ReadFile(flags.Arg(0))
	if err != nil {
		return a.fail(err)
	}
	temporary, err := os.MkdirTemp("", "hoolicy-catalog-publish-*")
	if err != nil {
		return a.fail(err)
	}
	defer os.RemoveAll(temporary)
	if err := os.WriteFile(filepath.Join(temporary, "catalog.json"), data, 0o600); err != nil {
		return a.fail(err)
	}
	digestReference, err := ocipack.PushCatalog(*reference, temporary, *signKey, *keyless, map[string]string{"org.opencontainers.image.title": catalog.Name, "dev.openhoo.hoolicy.catalog.digest": sha256Digest(data)})
	if err != nil {
		return a.fail(err)
	}
	fmt.Fprintf(a.stdout, "Published and signed catalog %s with %d coordinates.\n", digestReference, len(catalog.Packs))
	return 0
}

func (a application) packCatalogPull(args []string) int {
	flags := flag.NewFlagSet("pack catalog pull", flag.ContinueOnError)
	flags.SetOutput(a.stderr)
	configPath := flags.String("config", "", "configuration path")
	output := flags.String("output", "", "repository-relative catalog output path")
	if err := flags.Parse(args); err != nil {
		return flagErrorCode(err)
	}
	if flags.NArg() != 1 {
		return a.fail(fmt.Errorf("usage: hoolicy pack catalog pull [--output path] <signed-oci-reference>"))
	}
	project, err := loadProject(*configPath)
	if err != nil {
		return a.fail(err)
	}
	temporary, err := os.MkdirTemp("", "hoolicy-catalog-*")
	if err != nil {
		return a.fail(err)
	}
	defer os.RemoveAll(temporary)
	manifestDigest, verifiedBy, err := ocipack.FetchCatalog(project.Root, flags.Arg(0), project.Trust, temporary)
	if err != nil {
		return a.fail(err)
	}
	catalogPath := filepath.Join(temporary, "catalog.json")
	catalog, err := config.LoadCatalog(catalogPath)
	if err != nil {
		return a.fail(err)
	}
	data, err := os.ReadFile(catalogPath)
	if err != nil {
		return a.fail(err)
	}
	relative := *output
	if relative == "" {
		relative = filepath.ToSlash(filepath.Join(".hoolicy", "catalogs", catalog.Name+".json"))
	}
	_, destination, err := safepath.Writable(project.Root, relative)
	if err != nil {
		return a.fail(err)
	}
	if err := writeReportFile(destination, data); err != nil {
		return a.fail(err)
	}
	lock := config.CatalogLock{Version: config.CurrentVersion, Source: flags.Arg(0), ManifestDigest: manifestDigest, CatalogDigest: sha256Digest(data), VerifiedBy: verifiedBy}
	if err := config.SaveCatalogLock(destination+".lock", lock); err != nil {
		return a.fail(err)
	}
	fmt.Fprintf(a.stdout, "Pulled signed catalog %s with %d coordinates to %s.\n", catalog.Name, len(catalog.Packs), relative)
	return 0
}

func (a application) packCatalogVerify(args []string) int {
	flags := flag.NewFlagSet("pack catalog verify", flag.ContinueOnError)
	flags.SetOutput(a.stderr)
	if err := flags.Parse(args); err != nil {
		return flagErrorCode(err)
	}
	if flags.NArg() != 1 {
		return a.fail(fmt.Errorf("usage: hoolicy pack catalog verify <catalog.json>"))
	}
	catalog, lock, err := verifiedCatalog(flags.Arg(0))
	if err != nil {
		return a.fail(err)
	}
	fmt.Fprintf(a.stdout, "Verified signed catalog %s: %d coordinates, manifest %s, trust %s.\n", catalog.Name, len(catalog.Packs), lock.ManifestDigest, lock.VerifiedBy)
	return 0
}

func (a application) packCatalogResolve(args []string) int {
	flags := flag.NewFlagSet("pack catalog resolve", flag.ContinueOnError)
	flags.SetOutput(a.stderr)
	release := flags.String("release", "", "recommended semantic release")
	if err := flags.Parse(args); err != nil {
		return flagErrorCode(err)
	}
	if flags.NArg() != 2 {
		return a.fail(fmt.Errorf("usage: hoolicy pack catalog resolve [--release version] <catalog.json> <pack-name>"))
	}
	catalog, _, err := verifiedCatalog(flags.Arg(0))
	if err != nil {
		return a.fail(err)
	}
	var candidates []config.CatalogEntry
	for _, entry := range catalog.Packs {
		if entry.Name == flags.Arg(1) && (*release == "" || entry.Release == *release) {
			candidates = append(candidates, entry)
		}
	}
	if len(candidates) == 0 {
		return a.fail(fmt.Errorf("catalog has no matching coordinate"))
	}
	sort.Slice(candidates, func(i, j int) bool { return semanticReleaseLess(candidates[j].Release, candidates[i].Release) })
	selected := candidates[0]
	fmt.Fprintf(a.stdout, "%s %s %s\n", selected.Name, selected.Release, selected.OCI)
	return 0
}

func verifiedCatalog(path string) (*config.Catalog, *config.CatalogLock, error) {
	catalog, err := config.LoadCatalog(path)
	if err != nil {
		return nil, nil, err
	}
	lock, err := config.LoadCatalogLock(path + ".lock")
	if err != nil {
		return nil, nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	if sha256Digest(data) != lock.CatalogDigest {
		return nil, nil, errors.New("catalog digest mismatch")
	}
	return catalog, lock, nil
}

func semanticReleaseLess(left, right string) bool {
	comparison, err := config.CompareSemanticVersions(left, right)
	return err == nil && comparison < 0
}

func (a application) packPublish(ctx context.Context, args []string) int {
	flags := flag.NewFlagSet("pack publish", flag.ContinueOnError)
	flags.SetOutput(a.stderr)
	reference := flags.String("reference", "", "OCI registry reference with immutable release tag")
	previousPath := flags.String("previous", "", "previous pack used for compatibility report")
	provenance := flags.String("provenance", "", "immutable provenance reference or digest")
	signKey := flags.String("sign-key", "", "Cosign private key or KMS URI")
	keyless := flags.Bool("keyless", false, "use ambient keyless Sigstore identity")
	if err := flags.Parse(args); err != nil {
		return flagErrorCode(err)
	}
	if flags.NArg() != 1 || *reference == "" || *provenance == "" {
		return a.fail(fmt.Errorf("usage: hoolicy pack publish --reference registry/repo:tag --provenance ref (--sign-key key|--keyless) <pack>"))
	}
	if (*signKey == "") == !*keyless {
		return a.fail(fmt.Errorf("exactly one --sign-key or --keyless is required"))
	}
	if err := ocipack.ValidateProvenanceReference(*provenance); err != nil {
		return a.fail(err)
	}
	if err := config.ValidateOCIReference(*reference); err != nil {
		return a.fail(fmt.Errorf("publish reference: %w", err))
	}
	packPath := flags.Arg(0)
	pack, err := config.LoadPack(packPath)
	if err != nil {
		return a.fail(err)
	}
	if !strings.HasSuffix(*reference, ":"+pack.Release) {
		return a.fail(fmt.Errorf("publish reference tag must equal pack release %s", pack.Release))
	}
	verification := policytest.Run(ctx, packPath, a.registry)
	if len(verification.Errors) > 0 || verification.Passed != verification.Cases {
		return a.fail(fmt.Errorf("fixture suite failed: %s", strings.Join(verification.Errors, "; ")))
	}
	if findings := policylint.Pack(pack, nil, nil); len(findings) > 0 {
		return a.fail(fmt.Errorf("pack lint has %d unresolved findings", len(findings)))
	}
	snapshot, err := policytest.BuildSnapshot(ctx, packPath, a.registry)
	if err != nil {
		return a.fail(err)
	}
	snapshotData, err := policytest.SnapshotJSON(snapshot)
	if err != nil {
		return a.fail(err)
	}
	reviewedSnapshot, err := os.ReadFile(filepath.Join(packPath, "tests", "snapshot.json"))
	if err != nil {
		return a.fail(fmt.Errorf("reviewed behavior snapshot is required: %w", err))
	}
	if !bytes.Equal(reviewedSnapshot, snapshotData) {
		return a.fail(fmt.Errorf("behavior snapshot differs; review and run pack snapshot --update explicitly"))
	}
	comparison := emptyPackComparison("", pack.Release)
	if *previousPath != "" {
		previous, err := config.LoadPack(*previousPath)
		if err != nil {
			return a.fail(err)
		}
		if previous.Name != pack.Name {
			return a.fail(fmt.Errorf("previous pack name differs"))
		}
		comparison = comparePackRules(previous, pack)
		left, leftErr := policytest.BuildSnapshot(ctx, *previousPath, a.registry)
		if leftErr == nil {
			comparison.BehaviorChanged = compareSnapshotCases(left, snapshot)
		}
	}
	compatibilityData, _ := json.MarshalIndent(comparison, "", "  ")
	compatibilityData = append(compatibilityData, '\n')
	testResult := map[string]any{"version": 1, "pack": pack.Name, "release": pack.Release, "cases": verification.Cases, "passed": verification.Passed, "snapshotSha256": sha256Digest(snapshotData)}
	testData, _ := json.MarshalIndent(testResult, "", "  ")
	testData = append(testData, '\n')
	archive, packDigest, err := packarchive.Build(packPath)
	if err != nil {
		return a.fail(err)
	}
	releaseManifest := map[string]any{"version": 1, "pack": pack.Name, "release": pack.Release, "maturity": pack.Maturity, "owner": pack.Owner, "compatibilityNotes": pack.CompatibilityNotes, "artifactType": packarchive.ArtifactType, "packMediaType": packarchive.MediaType, "packDigest": packDigest, "compatibilityDigest": sha256Digest(compatibilityData), "testResultsDigest": sha256Digest(testData), "provenance": *provenance}
	releaseData, _ := json.MarshalIndent(releaseManifest, "", "  ")
	releaseData = append(releaseData, '\n')
	temporary, err := os.MkdirTemp("", "hoolicy-publish-*")
	if err != nil {
		return a.fail(err)
	}
	defer os.RemoveAll(temporary)
	for name, data := range map[string][]byte{"pack.tar.gz": archive, "release-manifest.json": releaseData, "compatibility.json": compatibilityData, "test-results.json": testData} {
		if err := os.WriteFile(filepath.Join(temporary, name), data, 0o600); err != nil {
			return a.fail(err)
		}
	}
	digestReference, err := ocipack.Push(*reference, temporary, *signKey, *keyless, map[string]string{"org.opencontainers.image.title": pack.Name, "org.opencontainers.image.version": pack.Release, "dev.openhoo.hoolicy.pack.digest": packDigest})
	if err != nil {
		return a.fail(err)
	}
	fmt.Fprintf(a.stdout, "Published and signed %s (%s).\n", digestReference, packDigest)
	return 0
}

func sha256Digest(data []byte) string {
	hash := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(hash[:])
}

func (a application) packInit(ctx context.Context, args []string) int {
	flags := flag.NewFlagSet("pack init", flag.ContinueOnError)
	flags.SetOutput(a.stderr)
	name := flags.String("name", "", "lowercase pack name")
	release := flags.String("release", "0.1.0", "initial semantic release")
	if err := flags.Parse(args); err != nil {
		return flagErrorCode(err)
	}
	if flags.NArg() != 1 {
		return a.fail(fmt.Errorf("usage: hoolicy pack init [--name name] [--release version] <directory>"))
	}
	directory, err := filepath.Abs(flags.Arg(0))
	if err != nil {
		return a.fail(err)
	}
	if *name == "" {
		*name = strings.ToLower(strings.NewReplacer(" ", "-", "_", "-").Replace(filepath.Base(directory)))
	}
	probe := config.Project{Version: config.CurrentVersion, Project: *name, FailOn: sdk.SeverityError}
	if err := probe.Validate(); err != nil {
		return a.fail(fmt.Errorf("invalid pack name: %w", err))
	}
	if _, err := os.Lstat(directory); err == nil {
		return a.fail(fmt.Errorf("%s already exists", directory))
	} else if !errors.Is(err, os.ErrNotExist) {
		return a.fail(err)
	}
	pack := config.Pack{
		Version: config.CurrentVersion, Name: *name, Release: *release,
		Description: "Repository policy pack for " + *name + ".", Maturity: "experimental", Owner: "replace-with-responsible-team", CompatibilityNotes: "Experimental behavior; review snapshots before each release and replace placeholder ownership.",
		Compatibility: config.Compatibility{Config: ">=1 <2", Hoolicy: scaffoldHoolicyCompatibility(a.info.Version)},
		Rules: []sdk.Rule{{
			ID: *name + ".required-file", Title: "Required repository file exists",
			Description: "Requires one reviewed repository file.", Rationale: "Contributors need a stable, documented repository entry point.",
			Remediation: "Add REQUIRED.md with reviewed project guidance.", Severity: sdk.SeverityError, Kind: "files", Files: []string{"REQUIRED.md"},
			Spec: map[string]any{"mode": "require", "message": "REQUIRED.md is required"},
		}},
	}
	if err := os.MkdirAll(filepath.Join(directory, "tests"), 0o755); err != nil {
		return a.fail(err)
	}
	complete := false
	defer func() {
		if !complete {
			_ = os.RemoveAll(directory)
		}
	}()
	packPath := filepath.Join(directory, "pack.yaml")
	if err := config.SavePack(packPath, pack); err != nil {
		return a.fail(err)
	}
	packData, err := os.ReadFile(packPath)
	if err != nil {
		return a.fail(err)
	}
	packData = append([]byte("# yaml-language-server: $schema=https://raw.githubusercontent.com/openhoo/hoolicy/main/schemas/v1/pack.schema.json\n"), packData...)
	if err := writeReportFile(packPath, packData); err != nil {
		return a.fail(err)
	}
	cases := fmt.Sprintf(`# yaml-language-server: $schema=https://raw.githubusercontent.com/openhoo/hoolicy/main/schemas/v1/pack-tests.schema.json
version: 1
cases:
  - name: required file passes
    rule: %s.required-file
    outcome: pass
    files:
      REQUIRED.md: |
        # Required guidance
    findingCount: 0
  - name: missing required file fails
    rule: %s.required-file
    outcome: fail
    files: {}
    findingCount: 1
    expect:
      - messageContains: required
        hasFix: false
`, *name, *name)
	readme := fmt.Sprintf("# %s policy pack\n\nRun `hoolicy test .`, `hoolicy lint .`, and `hoolicy pack snapshot --update .` before release.\n", *name)
	if err := writeReportFile(filepath.Join(directory, "tests", "cases.yaml"), []byte(cases)); err != nil {
		return a.fail(err)
	}
	if err := writeReportFile(filepath.Join(directory, "README.md"), []byte(readme)); err != nil {
		return a.fail(err)
	}
	if _, err := config.LoadPack(directory); err != nil {
		return a.fail(err)
	}
	result := policytest.Run(ctx, directory, a.registry)
	if len(result.Errors) > 0 {
		return a.fail(fmt.Errorf("generated pack tests failed: %s", strings.Join(result.Errors, "; ")))
	}
	complete = true
	fmt.Fprintf(a.stdout, "Created pack %s at %s with mandatory pass/fail fixtures.\n", *name, directory)
	return 0
}

func scaffoldHoolicyCompatibility(version string) string {
	version = strings.TrimPrefix(version, "v")
	if comparison, err := config.CompareSemanticVersions(version, "1.0.0"); err == nil && comparison >= 0 {
		return ">=1.0.0 <2.0.0"
	}
	if comparison, err := config.CompareSemanticVersions(version, "0.2.0"); err == nil && comparison >= 0 {
		return ">=0.2.0 <2.0.0"
	}
	return ">=0.1.3-0 <0.1.3 || >=0.2.0 <2.0.0"
}

func (a application) packSnapshot(ctx context.Context, args []string) int {
	flags := flag.NewFlagSet("pack snapshot", flag.ContinueOnError)
	flags.SetOutput(a.stderr)
	update := flags.Bool("update", false, "explicitly replace the reviewed behavior snapshot")
	if err := flags.Parse(args); err != nil {
		return flagErrorCode(err)
	}
	if flags.NArg() != 1 {
		return a.fail(fmt.Errorf("usage: hoolicy pack snapshot [--update] <pack-directory>"))
	}
	path := flags.Arg(0)
	verification := policytest.Run(ctx, path, a.registry)
	if len(verification.Errors) > 0 {
		return a.fail(fmt.Errorf("pack tests failed: %s", strings.Join(verification.Errors, "; ")))
	}
	snapshot, err := policytest.BuildSnapshot(ctx, path, a.registry)
	if err != nil {
		return a.fail(err)
	}
	data, err := policytest.SnapshotJSON(snapshot)
	if err != nil {
		return a.fail(err)
	}
	snapshotPath := filepath.Join(path, "tests", "snapshot.json")
	current, readErr := os.ReadFile(snapshotPath)
	if !*update {
		if readErr == nil && bytes.Equal(current, data) {
			fmt.Fprintf(a.stdout, "Behavior snapshot matches %s.\n", snapshotPath)
			return 0
		}
		if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
			return a.fail(readErr)
		}
		fmt.Fprint(a.stdout, string(data))
		fmt.Fprintln(a.stdout, "Snapshot differs or is missing. Review it, then re-run with --update.")
		return 1
	}
	if err := writeReportFile(snapshotPath, data); err != nil {
		return a.fail(err)
	}
	fmt.Fprintf(a.stdout, "Updated reviewed behavior snapshot %s.\n", snapshotPath)
	return 0
}

type packComparison struct {
	Previous          string   `json:"previous"`
	Current           string   `json:"current"`
	Added             []string `json:"added"`
	Removed           []string `json:"removed"`
	Renamed           []string `json:"renamed"`
	SeverityChanged   []string `json:"severityChanged"`
	BehaviorChanged   []string `json:"behaviorChanged"`
	ParametersChanged []string `json:"parametersChanged"`
	ControlsChanged   []string `json:"controlsChanged"`
	MetadataChanged   []string `json:"metadataChanged"`
}

func (a application) packCompare(ctx context.Context, args []string) int {
	flags := flag.NewFlagSet("pack compare", flag.ContinueOnError)
	flags.SetOutput(a.stderr)
	format := flags.String("format", "text", "text or json")
	if err := flags.Parse(args); err != nil {
		return flagErrorCode(err)
	}
	if flags.NArg() != 2 {
		return a.fail(fmt.Errorf("usage: hoolicy pack compare [--format text|json] <previous> <current>"))
	}
	previous, err := config.LoadPack(flags.Arg(0))
	if err != nil {
		return a.fail(err)
	}
	current, err := config.LoadPack(flags.Arg(1))
	if err != nil {
		return a.fail(err)
	}
	if previous.Name != current.Name {
		return a.fail(fmt.Errorf("pack names differ: %s and %s", previous.Name, current.Name))
	}
	comparison := comparePackRules(previous, current)
	leftSnapshot, leftErr := policytest.BuildSnapshot(ctx, flags.Arg(0), a.registry)
	rightSnapshot, rightErr := policytest.BuildSnapshot(ctx, flags.Arg(1), a.registry)
	if leftErr == nil && rightErr == nil {
		comparison.BehaviorChanged = compareSnapshotCases(leftSnapshot, rightSnapshot)
	}
	if (leftErr == nil) != (rightErr == nil) {
		comparison.BehaviorChanged = append(comparison.BehaviorChanged, "fixture suite availability changed")
	}
	if *format == "json" {
		data, _ := json.MarshalIndent(comparison, "", "  ")
		fmt.Fprintln(a.stdout, string(data))
		return 0
	}
	if *format != "text" {
		return a.fail(fmt.Errorf("unknown pack comparison format %q", *format))
	}
	fmt.Fprintf(a.stdout, "%s %s -> %s\n", previous.Name, previous.Release, current.Release)
	for _, item := range comparison.Added {
		fmt.Fprintf(a.stdout, "ADDED %s\n", item)
	}
	for _, item := range comparison.Removed {
		fmt.Fprintf(a.stdout, "REMOVED %s\n", item)
	}
	for _, item := range comparison.Renamed {
		fmt.Fprintf(a.stdout, "RENAMED %s\n", item)
	}
	for _, item := range comparison.SeverityChanged {
		fmt.Fprintf(a.stdout, "SEVERITY %s\n", item)
	}
	for _, item := range comparison.BehaviorChanged {
		fmt.Fprintf(a.stdout, "BEHAVIOR %s\n", item)
	}
	for _, item := range comparison.ParametersChanged {
		fmt.Fprintf(a.stdout, "PARAMETER %s\n", item)
	}
	for _, item := range comparison.ControlsChanged {
		fmt.Fprintf(a.stdout, "CONTROL %s\n", item)
	}
	for _, item := range comparison.MetadataChanged {
		fmt.Fprintf(a.stdout, "METADATA %s\n", item)
	}
	fmt.Fprintf(a.stdout, "\n%d added, %d removed, %d renamed, %d severity changes, %d behavior changes, %d parameter changes, %d control changes, %d metadata changes\n", len(comparison.Added), len(comparison.Removed), len(comparison.Renamed), len(comparison.SeverityChanged), len(comparison.BehaviorChanged), len(comparison.ParametersChanged), len(comparison.ControlsChanged), len(comparison.MetadataChanged))
	return 0
}

func emptyPackComparison(previous, current string) packComparison {
	return packComparison{Previous: previous, Current: current, Added: []string{}, Removed: []string{}, Renamed: []string{}, SeverityChanged: []string{}, BehaviorChanged: []string{}, ParametersChanged: []string{}, ControlsChanged: []string{}, MetadataChanged: []string{}}
}

func comparePackRules(previous, current *config.Pack) packComparison {
	result := emptyPackComparison(previous.Release, current.Release)
	if previous.Maturity != current.Maturity {
		result.MetadataChanged = append(result.MetadataChanged, "maturity "+previous.Maturity+" -> "+current.Maturity)
	}
	if previous.Owner != current.Owner {
		result.MetadataChanged = append(result.MetadataChanged, "owner changed")
	}
	if previous.CompatibilityNotes != current.CompatibilityNotes {
		result.MetadataChanged = append(result.MetadataChanged, "compatibility notes changed")
	}
	if previous.Compatibility != current.Compatibility {
		result.MetadataChanged = append(result.MetadataChanged, "compatibility range changed")
	}
	left := make(map[string]sdk.Rule)
	right := make(map[string]sdk.Rule)
	for _, rule := range previous.Rules {
		left[rule.ID] = rule
	}
	for _, rule := range current.Rules {
		right[rule.ID] = rule
	}
	for id, rule := range right {
		if old, exists := left[id]; exists {
			if old.Severity != rule.Severity {
				result.SeverityChanged = append(result.SeverityChanged, fmt.Sprintf("%s %s -> %s", id, old.Severity, rule.Severity))
			}
			oldControls, _ := json.Marshal(old.Controls)
			newControls, _ := json.Marshal(rule.Controls)
			if !bytes.Equal(oldControls, newControls) {
				result.ControlsChanged = append(result.ControlsChanged, id)
			}
			continue
		}
		renamedFrom := ""
		for oldID, old := range left {
			if _, retained := right[oldID]; !retained && old.Title == rule.Title && old.Kind == rule.Kind {
				renamedFrom = oldID
				break
			}
		}
		if renamedFrom != "" {
			result.Renamed = append(result.Renamed, renamedFrom+" -> "+id)
		} else {
			result.Added = append(result.Added, id)
		}
	}
	parameterNames := make(map[string]bool)
	for name := range previous.Parameters {
		parameterNames[name] = true
	}
	for name := range current.Parameters {
		parameterNames[name] = true
	}
	for name := range parameterNames {
		leftValue, leftExists := previous.Parameters[name]
		rightValue, rightExists := current.Parameters[name]
		leftData, _ := json.Marshal(leftValue)
		rightData, _ := json.Marshal(rightValue)
		if leftExists != rightExists || !bytes.Equal(leftData, rightData) {
			result.ParametersChanged = append(result.ParametersChanged, name)
		}
	}
	for id := range left {
		if _, exists := right[id]; !exists {
			renamed := false
			for _, value := range result.Renamed {
				if strings.HasPrefix(value, id+" -> ") {
					renamed = true
				}
			}
			if !renamed {
				result.Removed = append(result.Removed, id)
			}
		}
	}
	sort.Strings(result.Added)
	sort.Strings(result.Removed)
	sort.Strings(result.Renamed)
	sort.Strings(result.SeverityChanged)
	sort.Strings(result.ParametersChanged)
	sort.Strings(result.ControlsChanged)
	sort.Strings(result.MetadataChanged)
	return result
}

func compareSnapshotCases(previous, current *policytest.Snapshot) []string {
	left := make(map[string]string)
	right := make(map[string]string)
	for _, item := range previous.Cases {
		data, _ := json.Marshal(item)
		left[item.RuleID+"\x00"+item.Name] = string(data)
	}
	for _, item := range current.Cases {
		data, _ := json.Marshal(item)
		right[item.RuleID+"\x00"+item.Name] = string(data)
	}
	keys := make(map[string]bool)
	for key := range left {
		keys[key] = true
	}
	for key := range right {
		keys[key] = true
	}
	var changed []string
	for key := range keys {
		if left[key] != right[key] {
			changed = append(changed, strings.ReplaceAll(key, "\x00", " / "))
		}
	}
	sort.Strings(changed)
	return changed
}

func (a application) packAdd(args []string) int {
	flags := flag.NewFlagSet("pack add", flag.ContinueOnError)
	flags.SetOutput(a.stderr)
	configPath := flags.String("config", "", "configuration path")
	gitURL := flags.String("git", "", "Git repository URL")
	ociReference := flags.String("oci", "", "OCI pack reference with explicit tag or digest")
	ref := flags.String("ref", "", "Git tag, branch, or commit")
	subdir := flags.String("subdir", "", "pack subdirectory")
	local := flags.String("path", "", "local pack path")
	if err := flags.Parse(args); err != nil {
		return flagErrorCode(err)
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
	reference := config.PackRef{Name: name, Path: *local, Git: *gitURL, Ref: *ref, Subdir: *subdir, OCI: *ociReference}
	project.Packs = append(project.Packs, reference)
	if err := project.Validate(); err != nil {
		return a.fail(err)
	}
	if reference.Git != "" || reference.OCI != "" {
		if _, err := packs.UpdateLock(project, []string{name}, a.info.Version); err != nil {
			return a.fail(err)
		}
	} else {
		if _, err := config.LoadPack(filepath.Join(project.Root, filepath.FromSlash(reference.Path))); err != nil {
			return a.fail(err)
		}
	}
	if _, err := a.engine.Validate(project); err != nil {
		return a.fail(fmt.Errorf("added pack is invalid: %w", err))
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
	apply := flags.Bool("apply", false, "apply the exact reviewed vendor and lock update")
	if err := flags.Parse(args); err != nil {
		return flagErrorCode(err)
	}
	project, err := loadProject(*configPath)
	if err != nil {
		return a.fail(err)
	}
	names := flags.Args()
	if len(names) == 0 {
		for _, entry := range project.Packs {
			if entry.Git != "" || entry.OCI != "" {
				names = append(names, entry.Name)
			}
		}
	}
	pruneOnly := false
	if len(names) == 0 {
		lockPath := filepath.Join(project.Root, config.DefaultLockfile)
		if _, err := os.Lstat(lockPath); errors.Is(err, os.ErrNotExist) {
			return a.fail(fmt.Errorf("no remote packs selected"))
		} else if err != nil {
			return a.fail(err)
		}
		pruneOnly = true
	}
	sort.Strings(names)
	previewProject, cleanup, err := packUpdatePreviewProject(project)
	if err != nil {
		return a.fail(err)
	}
	defer cleanup()
	previewLock, err := packs.UpdateLock(previewProject, names, a.info.Version)
	if err != nil {
		return a.fail(err)
	}
	writePackUpdateReview(a.stdout, project, previewProject, previewLock, names)
	if !*apply {
		fmt.Fprintln(a.stdout, "Preview only. Re-run with --apply after reviewing rule, parameter, control, severity, and digest changes.")
		return 0
	}
	if _, err := packs.UpdateLock(project, names, a.info.Version); err != nil {
		return a.fail(err)
	}
	if _, err := a.engine.Validate(project); err != nil {
		return a.fail(fmt.Errorf("updated packs are invalid: %w", err))
	}
	if pruneOnly {
		fmt.Fprintf(a.stdout, "Pruned stale pack entries from %s; no remote packs are configured.\n", config.DefaultLockfile)
		return 0
	}
	fmt.Fprintf(a.stdout, "Updated and verified %d packs. Review vendored changes and %s.\n", len(names), config.DefaultLockfile)
	return 0
}

func packUpdatePreviewProject(project *config.Project) (*config.Project, func(), error) {
	temporary, err := os.MkdirTemp("", "hoolicy-update-preview-*")
	if err != nil {
		return nil, func() {}, err
	}
	cleanup := func() { _ = os.RemoveAll(temporary) }
	preview := *project
	preview.Root = temporary
	preview.Path = filepath.Join(temporary, config.DefaultFilename)
	if err := config.SaveProject(preview.Path, preview); err != nil {
		cleanup()
		return nil, func() {}, err
	}
	copyRelative := func(relative string) error {
		source := filepath.Join(project.Root, filepath.FromSlash(relative))
		if _, err := os.Lstat(source); errors.Is(err, os.ErrNotExist) {
			return nil
		} else if err != nil {
			return err
		}
		return copyPreviewPath(source, filepath.Join(temporary, filepath.FromSlash(relative)))
	}
	if err := copyRelative(config.DefaultLockfile); err != nil {
		cleanup()
		return nil, func() {}, err
	}
	if lock, err := config.LoadLock(filepath.Join(project.Root, config.DefaultLockfile)); err == nil {
		for _, entry := range lock.Packs {
			if err := copyRelative(entry.Vendor); err != nil {
				cleanup()
				return nil, func() {}, err
			}
		}
	}
	needsTrust := false
	for _, reference := range project.Packs {
		if reference.OCI != "" {
			needsTrust = true
		}
	}
	if needsTrust {
		if err := copyRelative(project.Trust); err != nil {
			cleanup()
			return nil, func() {}, err
		}
		_, trustPath, err := safepath.Existing(project.Root, project.Trust)
		if err != nil {
			cleanup()
			return nil, func() {}, err
		}
		trust, err := config.LoadTrust(trustPath)
		if err != nil {
			cleanup()
			return nil, func() {}, err
		}
		for _, requirement := range trust.Requirements {
			if requirement.Key != "" {
				if err := copyRelative(requirement.Key); err != nil {
					cleanup()
					return nil, func() {}, err
				}
			}
		}
	}
	return &preview, cleanup, nil
}

func copyPreviewPath(source, target string) error {
	info, err := os.Lstat(source)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("preview source contains symbolic link: %s", source)
	}
	if info.Mode().IsRegular() {
		data, err := os.ReadFile(source)
		if err != nil {
			return err
		}
		return writeReportFile(target, data)
	}
	if !info.IsDir() {
		return fmt.Errorf("preview source is not regular: %s", source)
	}
	return filepath.WalkDir(source, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		destination := filepath.Join(target, relative)
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("preview source contains symbolic link: %s", path)
		}
		if entry.IsDir() {
			return os.MkdirAll(destination, 0o755)
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("preview source is not regular: %s", path)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return writeReportFile(destination, data)
	})
}

func writePackUpdateReview(writer io.Writer, currentProject, previewProject *config.Project, previewLock *config.Lock, names []string) {
	currentLock, _ := config.LoadLock(filepath.Join(currentProject.Root, config.DefaultLockfile))
	oldEntries := make(map[string]config.LockedPack)
	if currentLock != nil {
		for _, entry := range currentLock.Packs {
			oldEntries[entry.Name] = entry
		}
	}
	newEntries := make(map[string]config.LockedPack)
	for _, entry := range previewLock.Packs {
		newEntries[entry.Name] = entry
	}
	selected := make(map[string]bool)
	for _, name := range names {
		selected[name] = true
	}
	for name := range oldEntries {
		if _, exists := newEntries[name]; !exists {
			selected[name] = true
		}
	}
	ordered := make([]string, 0, len(selected))
	for name := range selected {
		ordered = append(ordered, name)
	}
	sort.Strings(ordered)
	for _, name := range ordered {
		oldEntry, oldExists := oldEntries[name]
		newEntry, newExists := newEntries[name]
		if !newExists {
			fmt.Fprintf(writer, "REMOVE %s lock and vendored pack\n", name)
			continue
		}
		fmt.Fprintf(writer, "DIGEST %s manifest %s -> %s; pack %s -> %s; release %s -> %s\n", name, fallback(oldEntry.ManifestDigest, oldEntry.Commit), fallback(newEntry.ManifestDigest, newEntry.Commit), fallback(oldEntry.PackDigest, oldEntry.Digest), fallback(newEntry.PackDigest, newEntry.Digest), oldEntry.Release, newEntry.Release)
		if oldExists {
			oldPack, oldErr := config.LoadPack(filepath.Join(currentProject.Root, filepath.FromSlash(oldEntry.Vendor)))
			newPack, newErr := config.LoadPack(filepath.Join(previewProject.Root, filepath.FromSlash(newEntry.Vendor)))
			if oldErr == nil && newErr == nil {
				comparison := comparePackRules(oldPack, newPack)
				for _, item := range comparison.Added {
					fmt.Fprintf(writer, "ADDED %s\n", item)
				}
				for _, item := range comparison.Removed {
					fmt.Fprintf(writer, "REMOVED %s\n", item)
				}
				for _, item := range comparison.Renamed {
					fmt.Fprintf(writer, "RENAMED %s\n", item)
				}
				for _, item := range comparison.SeverityChanged {
					fmt.Fprintf(writer, "SEVERITY %s\n", item)
				}
				for _, item := range comparison.ParametersChanged {
					fmt.Fprintf(writer, "PARAMETER %s\n", item)
				}
				for _, item := range comparison.ControlsChanged {
					fmt.Fprintf(writer, "CONTROL %s\n", item)
				}
				for _, item := range comparison.MetadataChanged {
					fmt.Fprintf(writer, "METADATA %s\n", item)
				}
			}
		}
	}
}

func (a application) packVerify(ctx context.Context, args []string) int {
	flags := flag.NewFlagSet("pack verify", flag.ContinueOnError)
	flags.SetOutput(a.stderr)
	configPath := flags.String("config", "", "configuration path")
	if err := flags.Parse(args); err != nil {
		return flagErrorCode(err)
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
func (a application) unexpectedArguments(command string, args []string) int {
	return a.fail(fmt.Errorf("%s does not accept positional arguments: %s", command, strings.Join(args, " ")))
}
func flagErrorCode(err error) int {
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	return 2
}
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
func commandOutputLine(output []byte) string {
	value := strings.TrimSpace(strings.Map(func(character rune) rune {
		if unicode.IsControl(character) {
			return ' '
		}
		return character
	}, string(output)))
	if value == "" {
		return "command failed"
	}
	if at := strings.IndexByte(value, '@'); at >= 0 {
		if scheme := strings.LastIndex(value[:at], "://"); scheme >= 0 {
			value = value[:scheme+3] + "<redacted>@" + value[at+1:]
		}
	}
	runes := []rune(value)
	if len(runes) > 500 {
		value = string(runes[len(runes)-500:])
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

func writeReportFile(path string, data []byte) error {
	temporaryName, err := stageReportFile(path, data)
	if err != nil {
		return err
	}
	defer os.Remove(temporaryName)
	return os.Rename(temporaryName, path)
}

func stageReportFile(path string, data []byte) (string, error) {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return "", err
	}
	temporary, err := os.CreateTemp(directory, ".hoolicy-report-*")
	if err != nil {
		return "", err
	}
	temporaryName := temporary.Name()
	if err := temporary.Chmod(0o644); err != nil {
		closeErr := temporary.Close()
		_ = os.Remove(temporaryName)
		return "", errors.Join(err, closeErr)
	}
	if _, err := temporary.Write(data); err != nil {
		closeErr := temporary.Close()
		_ = os.Remove(temporaryName)
		return "", errors.Join(err, closeErr)
	}
	if err := temporary.Sync(); err != nil {
		closeErr := temporary.Close()
		_ = os.Remove(temporaryName)
		return "", errors.Join(err, closeErr)
	}
	if err := temporary.Close(); err != nil {
		_ = os.Remove(temporaryName)
		return "", err
	}
	return temporaryName, nil
}

func reserveReportPath(path string) (string, error) {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return "", err
	}
	temporary, err := os.CreateTemp(directory, ".hoolicy-signature-*")
	if err != nil {
		return "", err
	}
	name := temporary.Name()
	if err := temporary.Close(); err != nil {
		_ = os.Remove(name)
		return "", err
	}
	if err := os.Remove(name); err != nil {
		return "", err
	}
	return name, nil
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
