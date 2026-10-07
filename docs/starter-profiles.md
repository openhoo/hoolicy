# Offline starter profiles

Use a starter profile to write a reviewable project policy without downloading
packs or installing dependencies:

```sh
hoolicy init --list-profiles
hoolicy init --project billing --profile go-service
hoolicy validate
hoolicy check
hoolicy list
hoolicy explain go.dependencies
```

`init` creates `hoolicy.yaml` and `.hoolicy/waivers.yaml`. It refuses to
replace either existing file and rejects a symlinked waiver directory. It does
not create placeholder documentation or lockfiles to make a policy pass.
`--list-profiles` prints names and descriptions without creating a directory or
files. An unknown profile exits with code 2 before creating files.

## Choose a profile

| Profile | Included checks | Useful for |
| --- | --- | --- |
| `empty` | No rules | Writing a policy from scratch |
| `standard` | README, license, security policy, Conventional Commit and branch naming, approved artifact sources | General repositories |
| `strict` | Standard checks; literal container images require SHA-256 digests | Repositories with immutable container inputs |
| `go-library` | Standard checks; root `go.mod`, reviewed local replacements, release notes | Published or internal Go modules |
| `go-service` | Standard checks; root `go.mod`, reviewed local replacements, `go.sum`, operating runbook | Go services with dependency locks |
| `node-library` | Standard checks; root `package.json`, package locks, reviewed dependency sources, package identity and license, release notes | Published or internal JavaScript and TypeScript packages |
| `node-service` | Standard checks; root `package.json`, package locks, reviewed dependency sources, package identity and license, operating runbook | JavaScript and TypeScript services |
| `container-service` | Strict checks; root Dockerfile or Containerfile, `.dockerignore`, operating runbook | Services delivered as containers |

All profiles except `empty` inherit the same reviewed default source allowlists:
`docker.io` and `ghcr.io`, the public npm registry, and the public NuGet feed.
Review those allowlists for your organization before enforcement. Stack profiles
use the standard image policy unless you choose `container-service`; add
`requireDigest: true` to `supply-chain.approved-sources` when needed.

## What stack checks enforce

Go and Node profiles require a root manifest and inspect nested manifests as
well. Stack-specific rules exclude vendored policy files, `node_modules`, Go's
root `vendor` directory, and root `dist` and `build` output directories. Adjust
those exclusions for generated paths in your repository.

`go.dependencies` rejects local replacement targets unless their module names
appear in `allowedLocalDependencies`. The Go service profile requires a sibling
`go.sum` for each checked module. A dependency-free service may legitimately
have no `go.sum`; after review, set `requireLocks: false` rather than creating a
fake checksum file. The library profile permits no checksum file by default.

`node.dependencies` checks the authoritative lock for the declared package
manager (npm, pnpm, Yarn, or Bun), mutable dependency sources, and unreviewed
local edges. Internal workspace packages present in the matched manifests are
recognized. `node.metadata` requires nonempty string `name`, `version`, and
`license` fields; it does not assert a specific license or semantic version.
Private services can use a reviewed declaration such as `UNLICENSED` if that is
appropriate for the project.

Library release notes can live at `CHANGELOG.md` or `docs/changelog.md`. A service
runbook can live at `RUNBOOK.md` or `docs/runbook.md`. Container checks require a
root build definition and `.dockerignore`. These file-presence checks provide
discoverability; reviewers still need to evaluate their contents, and the
checks do not prove a successful deployment or recovery exercise.

## Customize the generated policy

Profiles write ordinary inline rules. Edit titles, severity, globs, allowlists,
and kind-specific specs in `hoolicy.yaml`, then run `hoolicy validate` and
`hoolicy check`. You can combine stack rules, add control mappings, or start a
new project with a different profile. Initialization does not merge into an
existing policy; edit that policy explicitly.

For shared organizational policy, move reviewed rules into a pack and vendor
it through the explicit pack workflow. Ordinary checks remain offline. See
[authoring-rules.md](authoring-rules.md) for rule specs and
[compatibility.md](compatibility.md) for exit codes and contract guarantees.
