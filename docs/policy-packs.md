# Policy packs

A pack groups parameterized rules without executable code.

```text
my-pack/
  pack.yaml
  tests/
    cases.yaml
```

`pack.yaml` requires version `1`, lowercase name, semantic `release`, description, parameter definitions, and rules. Every rule ID must start with `<pack-name>.`.

Supported parameter types: `string`, `string_list`, `bool`, and `number`. A string containing exactly `{{ parameter_name }}` is replaced while preserving the parameter type.

## Required tests

Every rule needs at least one fixture with `outcome: pass` and one with `outcome: fail`.

```yaml
version: 1
parameters:
  required_file: README.md
cases:
  - name: documented repository passes
    rule: repository.readme
    outcome: pass
    files:
      README.md: |
        # Demo
  - name: missing documentation fails
    rule: repository.readme
    outcome: fail
    files: {}
```

Test decoding is strict. Duplicate case names, unknown rules, missing outcomes, invalid fixture paths, and absent pass/fail coverage fail the pack.

```sh
hoolicy test ./my-pack
hoolicy pack verify ./my-pack
```

## Local packs

```yaml
packs:
  - name: my-pack
    path: policy/my-pack
    with:
      required_file: README.md
```

Local packs are convenient for repository-owned policy development.

## Git-vendored packs

```yaml
packs:
  - name: my-pack
    git: https://github.com/example/policy.git
    ref: v1.4.0
    subdir: packs/my-pack
    with:
      required_file: README.md
```

Run `hoolicy pack update my-pack`. Commit `hoolicy.lock` and `.hoolicy/vendor/my-pack`. CI checks remain offline. Changing the Git ref in configuration without refreshing the lock, changing vendored bytes, using a symbolic link, or changing pack identity fails validation.

Treat pack releases like APIs: document behavior changes, keep IDs stable, add regression fixtures before fixing a false positive, and make severity increases explicit in release notes.
