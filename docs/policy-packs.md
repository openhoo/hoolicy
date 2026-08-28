# Policy packs

A pack groups parameterized rules without executable code.

```text
my-pack/
  pack.yaml
  tests/
    cases.yaml
```

`pack.yaml` requires version `1`, lowercase name, semantic `release`, description, parameter definitions, and rules. Every rule ID must start with `<pack-name>.`.

Official packs declare `maturity` (`experimental`, `recommended`, or `stable`), accountable `owner`, compatibility ranges, and compatibility notes. Recommended and stable packs cannot omit owner or compatibility notes. Behavior snapshots expose finding changes before release.

Maturity is evidence-based. A new official pack remains `experimental` until its owner records measured results from multiple unrelated repositories, reviews every false positive and false negative found, and links that review from release notes. Current measurements and non-graduation decisions are recorded in [curated pack measurements](pack-measurements.md). Fixture coverage alone cannot graduate a pack. `recommended` means the measured scope is documented and operationally useful; `stable` additionally commits to the documented compatibility contract. Hoolicy validates required metadata but does not invent external adoption evidence.

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

Compatibility ranges support whitespace-separated intersections and `||` alternatives. Repository-owned packs may use a narrow prerelease alternative while developing the engine version that introduces them, for example `>=0.1.3-0 <0.1.3 || >=0.2.0 <2.0.0`. This admits VCS pseudo-versions built from the unreleased source, rejects stable `0.1.3`, and admits the real `0.2.0` release. Remove obsolete prerelease alternatives after the first compatible release support window ends.

## Signed OCI packs

`hoolicy pack publish` requires a release-tagged OCI coordinate, passing fixtures, clean lint, reviewed behavior snapshot, compatibility report, provenance reference, canonical archive, and exactly one signing mode. The signed release manifest binds pack digest, test results, compatibility report, maturity, owner, and provenance.

Consumers configure an OCI coordinate plus `.hoolicy/trust.yaml` requirement using either an exact key or exact identity and issuer. `pack update` resolves a tag once, verifies the digest reference, requires the exact Hoolicy artifact type and complete layer-media-type set, extracts only a bounded canonical archive, previews digest/rule/severity/parameter/control/maturity changes, and writes only with `--apply`. Later validation is offline against the exact lock and vendor digest.

Signed static catalogs recommend pack release coordinates. `pack catalog pull` requires the dedicated catalog artifact and layer media types, then records catalog content digest, OCI manifest digest, and verified identity. Catalog selection never overrides the consuming repository lock.
