# Predefined policy packs

Hoolicy ships reviewable, offline policy packs in `packs/`. Install the packs
that match the repository's delivery model and set their parameters explicitly.
A pack adds rules only when referenced by the consuming project's policy.
No pack downloads code during an ordinary check.

## Choose a pack

| Pack | Purpose | Configuration to review | Maturity |
| --- | --- | --- | --- |
| `repository` | Branch, commit, and merge-request naming | Naming patterns, exempt branches, length limits | Stable |
| `repository-hygiene` | Unresolved source conflicts, merge backups, desktop caches | Owned source globs and fixture exclusions | Experimental |
| `secrets-prevention` | Narrow private-key and provider-token signatures; credential files | Scan extensions, template allowlist, reviewed fixture exclusions | Experimental |
| `supply-chain` | Approved artifact sources and expiring security exceptions | Registry hosts, dependency source URLs, digest requirement | Stable |
| `dependency-governance` | npm, Cargo, and Go dependency resolution and licensing | Lock requirement, licenses, reviewed local edges | Experimental |
| `container-build` | Immutable approved base images and risky build inputs | Container files, approved registries, actual context ignore file | Experimental |
| `ci-workflow-security` | GitHub Actions and GitLab CI trust boundaries | Allowed write permissions and job timeouts | Experimental |
| `deployment-invariants` | Kubernetes, Compose, and Terraform deployment invariants | Provider-specific parameters and selected deployment files | Experimental |
| `product-quality` | Translation parity and semantic acceptance classes | Language manifest, catalogs, feature scope, scenario tags | Stable |
| `acceptance-coverage` | Failure, accessibility, and security acceptance intent | Feature scope, dialect, organization tag vocabulary | Experimental |
| `api-contract-hygiene` | OpenAPI consumption evidence bound to contract digest | Contract, evidence file, producer identity, migration settings | Experimental |
| `artifact-evidence` | Release evidence bound to repository and artifact digests | Artifact paths, producer identities, evidence requirements | Experimental |
| `structured-configuration` | Typed production settings, availability bounds, and browser trust | Service config paths, replica minimum, timeout maximum, actual field contract | Experimental |

Experimental packs need measured review on unrelated repositories before they
can graduate. Passing synthetic fixtures establishes bounded behavior, not
production suitability. See [pack measurements](pack-measurements.md).

## Adopt the additional packs

For local development, keep the selected directories under `policy/` in the
consuming repository and reference them in `hoolicy.yaml`:

```yaml
version: 1
project: my-service
failOn: error
packs:
  - name: repository-hygiene
    path: policy/repository-hygiene
    with:
      source_globs: ['src/**/*.{ts,tsx}', 'scripts/**/*.sh']
      excluded_paths: ['tests/fixtures/merge-conflict.ts']
  - name: secrets-prevention
    path: policy/secrets-prevention
    with:
      scan_globs: ['src/**/*.{ts,tsx}', 'scripts/**/*.sh', 'certs/**/*.pem']
      allowed_env_templates: ['.env.example']
      excluded_paths: []
  - name: container-build
    path: policy/container-build
    with:
      dockerfiles: [Dockerfile]
      dockerignore_paths: [.dockerignore]
      registries: [ghcr.io]
  - name: acceptance-coverage
    path: policy/acceptance-coverage
    with:
      feature_globs: ['features/account/**/*.feature']
      gherkin_language: en
      failure_tags: ['@failure']
      accessibility_tags: ['@accessibility']
      security_tags: ['@authorization']
```

The selected feature scope should contain product behavior for which all three
scenario classes are meaningful. Do not enable every class on unrelated backend
features merely to fill the tag vocabulary. If only one class applies, use
`product-quality` with the corresponding `required_scenario_tags`, or a local
rule using `gherkin.requirements`.

For Git-vendored installation, use the official repository's published release
tag containing the selected pack and the corresponding `packs/<name>` subdirectory.
Preview the update, review its digest and rule changes, then apply and commit the
lockfile and vendored content. The full workflow is in
[policy packs](policy-packs.md).

## Repository hygiene: three rules

- `repository-hygiene.conflict-markers` blocks line-anchored opening and closing
  Git conflict boundaries in source files. Inline strings and commented examples
  pass. Default globs cover common source extensions. Structured configuration
  and prose need a separately reviewed scope; no broad repository scan is implied.
- `repository-hygiene.merge-debris` warns on `.orig` and `.rej` artifacts.
- `repository-hygiene.desktop-debris` warns on `.DS_Store` and `Thumbs.db`.

Intentional parser fixtures should have exact exclusions. Removing a finding
from the current snapshot does not remove its contents from Git history.

## Secrets prevention: three rules

- `secrets-prevention.private-key-material` blocks PEM private-key begin markers,
  including encrypted and OpenSSH private keys. Certificates and public keys
  pass. A match is reported with a file location and stable finding key; the
  matched key text is not included in the finding message.
- `secrets-prevention.provider-token-signatures` blocks bounded classic GitHub
  and GitLab token-shaped literals. Short placeholders, environment references,
  and longer unrelated identifiers pass. Fixtures use synthetic characters and
  contain no working credentials.
- `secrets-prevention.credential-files` blocks common SSH private-key filenames,
  PKCS12 `.p12`/`.pfx` containers, `.env`, and `.env.*`. Only configured template
  paths and reviewed exclusions are allowed.

Default text scans cover source, Markdown, plain text, PEM, and key-file
extensions. They do not claim to scan binaries, arbitrary extensionless files,
JSON/YAML configuration, Git history, every provider token format, or secrets
without a recognizable signature. Broader coverage belongs to a dedicated
secret scanner; Hoolicy can govern its exact evidence separately.

The credential-file rule checks filenames, so a harmless `.env.production` or
synthetic `.pfx` fixture still fails unless explicitly excluded. A template
allowlist allows a filename; it does not establish that the template is secret
free. Keep its values as placeholders and include its contents in a separately
reviewed scanner scope when needed. If an actual secret is found, revoke or
rotate it after removing it from the current files.

## Container builds: four rules

- `container-build.immutable-base-images` requires approved registry hosts and
  `sha256` pins on literal external `FROM` inputs. Parsed local stage references
  and `scratch` remain valid. This shares the maintained `sources.allowed`
  parser; digest pins establish identity, not image safety.
- `container-build.context-ignore` warns when none of the configured ignore-file
  alternatives exists. Select the file for the context actually passed to the
  builder. Multiple paths are alternatives, not a requirement for every context.
  The rule does not interpret ignore patterns or establish protection against
  accidental secret inclusion.
- `container-build.remote-add` warns on direct, single-line HTTP(S) `ADD` inputs,
  including instruction flags. Local archives and commented examples pass.
  Reviewed checksum-bearing remote `ADD` still needs a narrow exception.
- `container-build.download-pipe-shell` blocks direct single-line `RUN curl … |
  sh` and `RUN wget … | bash` patterns, including `/bin/` shell paths and RUN
  flags. Quoted header pipes and escaped literal pipes pass; quoted URLs with an
  actual shell pipe fail. A separate download with checksum verification passes.

The two text rules intentionally check narrow visible constructs. They do not
parse shell scripts, follow multiline continuations, inspect arbitrary command
chains, determine whether a preceding checksum command is correct, or prove
runtime isolation. Use `deployment-invariants` for its supported runtime
controls and a container scanner for image contents.

## Acceptance coverage: three rules

- `acceptance-coverage.failure-scenarios` requires the configured failure tags.
- `acceptance-coverage.accessibility-scenarios` requires accessibility tags.
- `acceptance-coverage.security-scenarios` requires security-boundary tags.

Each rule parses Gherkin and requires at least one scenario in each selected
feature, with every configured tag represented somewhere in its scenarios.
The configured dialect is checked, including localized Gherkin. A tag mentioned
only in feature prose or a step cannot satisfy coverage. Default tags are
`@failure`, `@accessibility`, and `@security`; every rule starts at warning.

Tags express reviewed acceptance intent. These rules do not execute steps or
establish that assertions are effective, that a product conforms to accessibility
standards, or that authorization is correct. Run the corresponding acceptance
suite and capture real evidence. Empty file selection passes as with other
file-scoped semantic rules; add a repository-owned `files` requirement when the
absence of feature files must block delivery.

## Structured configuration: four rules

This pack supplies an explicit example production configuration contract using
`structured.fields` and bounded CEL. It requires `environment: production`,
`debug: false`, integer `replicas` (default minimum 2), and a positive integer
`timeoutMs` (default maximum 30000). It also requires a nonempty unique
`allowedOrigins` array, with nonempty string entries free of wildcards, and
forbids the `insecureSkipVerify` field even when false or null. Origins are not
parsed as URLs and no browser or TLS behavior is executed.

By default it selects exact `config/production.json`, `config/production.yaml`,
`config/production.yml`, or `config/production.toml` files. Override
`configuration_files`, `minimum_replicas`, and `maximum_timeout_ms` explicitly.
These filenames are alternatives; each matched file and each YAML document
must satisfy the contract. No files produces a finding. Malformed or duplicate
keys are operational errors. Adapt the field pointers in a repository-owned
copy when the application's actual configuration contract differs.

This pack needs Hoolicy 0.5 or newer. The standalone
[structured example](../examples/structured-configuration/) demonstrates the
rule without acquiring a pack, including required array members.

## Verify before enforcing

Run the selected pack fixture suites, verify pack structure, check reviewed
snapshots, and lint each pack:

```sh
hoolicy test policy/repository-hygiene policy/secrets-prevention policy/container-build policy/acceptance-coverage
hoolicy pack verify policy/secrets-prevention
hoolicy pack snapshot policy/secrets-prevention
hoolicy lint policy/secrets-prevention
hoolicy check
```

The additional packs include positive, negative, and boundary fixtures with
expected rule IDs, reasons, keys, paths, and waiver/fix properties. Snapshots
preserve their observed decisions. Inspect actual repository findings and
review false positives before making advisory rules block delivery. Keep
exceptions narrow, accountable, and expiring; see [authoring rules](authoring-rules.md).
