# Authoring useful rules

Good policy checks an objective, reviewable invariant with clear failure ownership. Bad policy encodes taste, duplicates a compiler, or rewards superficial edits.

Use a rule when all are true:

- Repository evidence can decide it deterministically.
- A failure identifies real risk or missing delivery evidence.
- Remediation tells a contributor what outcome to produce.
- Exceptions can be narrowed and expire.
- False positives stay low enough that teams will not normalize bypasses.

Avoid rules such as minimum README length, mandatory comments, exact prose, indentation regexes, arbitrary file-count targets, framework preferences without risk rationale, or tags that can be added without implementing the scenario. Prefer parsing structured formats and measuring semantics.

## Common rule fields

Every rule requires `id`, `title`, `description`, `rationale`, `remediation`, `severity`, `kind`, and a kind-specific `spec`. IDs use lowercase dot or hyphen segments. Packs must prefix IDs with their pack name.

`severity` describes impact. `failOn` describes enforcement threshold. Start uncertain policies at `warning`; move to `error` after measuring false positives and documenting ownership.

Optional `controls` map evidence to a real control without claiming certification:

```yaml
controls:
  - framework: internal-security-baseline
    id: SC-04
```

## Core kinds

### `files`

Requires, forbids, or counts glob matches. `mode` is `require`, `forbid`, or `count`; count accepts `minimum` and `maximum`. A require rule may offer one safe `create` edit.

### `text`

Applies RE2-compatible `require` and `forbid` expressions to matched text files. Best for narrow literals and legacy formats, not structured documents.

### `structured.cel`

Parses JSON, YAML, TOML, XML, dotenv, or INI and evaluates CEL. Variables:

- `documents` and alias `items`: `{path, index, line, column, data}` records.
- `files`: `{path, size, sha256}` metadata.
- `repo`: repository root and project directory name.
- `git`: branch, commit, dirty state, and merge-request title.
- `params`: project parameters.
- `now`: timestamp.

Expression returns `true` for pass, `false` for one finding, or a list of objects with optional `message`, `path`, `key`, `line`, and `column`. Default cost limit is 100,000; maximum is 1,000,000.

```yaml
kind: structured.cel
files: [deploy/*.yaml]
spec:
  expression: documents.all(d, d.data.replicas >= 2)
  message: Production deployments need at least two replicas
  costLimit: 50000
```

### `git.naming`

Checks `branchPattern`, `allowedBranches`, `commitPattern`, `mergeRequestTitlePattern`, and `mergeRequestTitleMaximum`. Commit-range checks use `--base` or supported CI environment variables.

### `manifest.consistency`

Compares one authoritative JSON pointer against target file pointers. Empty pointer selects document root. Scalar JSON targets can receive hash-bound safe fixes.

### `sources.allowed`

Parses npm registry entries, NuGet XML sources, Dockerfile `FROM`, and structured `image` or `repository` values. Supports registry hosts in `registries`, absolute HTTP(S) URLs in `npm` and `nuget`, plus `requireDigest`. Credentials, URL queries, and fragments in allowlists are rejected.

### `exceptions.lifecycle`

Checks a structured exception collection for unique ID, meaningful reason, owner, absolute HTTPS ticket, creation date, expiry, and maximum lifetime.

### `i18n.parity`

Reads language codes from a manifest JSON pointer, flattens nested translation catalogs, then reports missing or empty keys per language.

### `gherkin.requirements`

Uses the official Gherkin parser. Checks dialect, `minimumScenarios`, tags that must appear somewhere with `requiredTags`, and tags required on every scenario with `eachScenarioAnyOf`.

## Waivers

Waivers live in `.hoolicy/waivers.yaml` by default:

```yaml
version: 1
waivers:
  - id: security.temporary-cve
    rule: supply-chain.exception-lifecycle
    fingerprints: [0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef]
    reason: Upstream fix is scheduled; compensating control blocks exposure.
    owner: security@example.com
    ticket: https://issues.example.com/SEC-123
    created: 2026-08-26
    expires: 2026-09-25
```

Prefer fingerprints. Path scopes are allowed but global patterns are rejected. Expired, invalid, duplicate, and stale waivers are blocking findings.
