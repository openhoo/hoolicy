# Additional rule choices in Hoolicy 0.5

## Offline starter profiles

Run `hoolicy init --list-profiles` before selecting a profile. `go-library` and
`go-service` require a root Go module and review dependency sources. Go service
profiles require go.sum; library profiles allow dependency-free modules.
`node-library` and `node-service` require package metadata and locks.
Library profiles require release notes; service profiles require a runbook.
`container-service` adds immutable image sources, a build definition, context
ignore-file presence, and a runbook. Presence does not prove document quality
or ignore-pattern effectiveness. All rules are embedded and editable.

## Typed structured fields

`structured.fields` parses JSON, YAML, and TOML. This is a rule fragment;
include normal id/title/description/rationale/remediation/severity fields:

```yaml
kind: structured.fields
files: [config/production.yaml]
spec:
  fields:
    - pointer: /debug
      required: true
      type: boolean
      allowedValues: [false]
    - pointer: /replicas
      required: true
      type: integer
      minimum: 2
    - pointer: /credentials/password
      forbidden: true
```

Pointers use `/` segments, `~1` for literal slash and `~0` for literal tilde;
the empty pointer selects the root. Missing optional fields skip checks,
explicit null is present, and `forbidden` rejects even a null value. Use
`required: true` when absence must fail. Types are string, number, integer,
boolean, array, object, and null. `allowedValues` compares complete values;
a singleton expresses equality. `pattern` checks a string with RE2.
`minimum`/`maximum` bound numbers; `minItems`/`maxItems`, `uniqueItems`, and
`requiredItems` constrain arrays. Forbidden fields cannot have other constraints.

All selected documents are checked. No selected files is a policy finding;
`allowNoFiles: true` explicitly allows optional selection. Malformed input is
exit 2, never accepted policy debt. Findings identify fields without revealing
actual values. Use bounded CEL for relationships or per-element predicates
that these field constraints do not express.

## Opt-in packs

| Pack | Checks | Limits |
| --- | --- | --- |
| repository-hygiene | Conflicts and merge/desktop debris | Selected inventory, no Git history |
| secrets-prevention | Narrow key/token markers and credential filenames | Partial signatures; rotate exposed secrets separately |
| container-build | Approved immutable bases and risky literal build inputs | Narrow single-line text patterns; ignore-file existence only |
| acceptance-coverage | Semantic failure/accessibility/security tags | Coverage intent, no execution or conformance proof |
| structured-configuration | Production/debug fields, numeric bounds, browser origins | Explicit sample config contract, adapt pointers to your service |

All five packs are experimental. Select actual repository decisions and tune
parameters before enforcement. Their default severities are intentional;
warning rules do not block an error threshold. Use `hoolicy list` and `explain`
to inspect instantiated scopes, then test positive and negative samples.

To acquire a pack, add a Git source with a approved release ref (Hoolicy 0.5
or newer for structured-configuration), the matching `subdir: packs/<name>`,
and the matching pack name. Preview `hoolicy pack update <name>`, review the
diff, apply with `--apply`, and commit the lock and vendored bytes. Ordinary
validate/check remains offline. Never silently switch a repository's approved
release or disable findings simply to get green.
