# Hoolicy post-release smoke testing — October 13, 2026

## Publication and scope

The first campaign was published as `v0.6.0`, with main and the peeled tag at
`77cf11ce64320be509913abf50383f0d4f2429f4`. Publication receipts verify all 14
assets, six payload checksums, seven Sigstore bundles, seven source-bound
attestations, the setup installer, the public Go module, the OCI image and all
version aliases. Actual downloaded native, public Go-installed, Linux arm64
and emulated Linux amd64 consumers passed 212 checks.

The requested second pass used the coordinator plus three specialists for
parser/CEL boundaries, pack/archive trust, and decision/report evidence.
Reproductions used the downloaded `v0.6.0` executable or its public module,
plus focused failing regressions. Pack transports were local test tools;
no test packs were published externally. Owners independently reviewed each
other's changes before the implementation was frozen for qualification.

## Corrections

| ID | Reproduced failure | Correction and regression boundary |
| --- | --- | --- |
| HSP-01 | A waiver created and expiring in 2099 suppressed a current finding and returned exit 0. | Reject future creation dates in current waiver validation; retain historical report migration against its original decision date. |
| HSP-02 | SDK findings with non-JSON properties or negative coordinates reached finalization; failed JSON digests collapsed to the hash of empty bytes. | Add finding validation before finalization and return an empty digest on encoding failure without changing existing digest signatures or valid golden values. |
| HSP-03 | Current and historical report validation accepted a weakened failure threshold. | Reject thresholds weaker than the matching project; accept valid stricter `--fail-on` results in both report versions. |
| HSP-04 | A waived finding could reference the correct rule and waiver ID while matching neither its fingerprint nor path scope. | Bind each waived finding to actual scope; rebind verified v1 identities when migrating them to v2. |
| HSP-05 | Report validation could accept a suppressed Hoolicy waiver/baseline lifecycle finding. | Lifecycle findings must remain new and unwaived. |
| HSP-06 | V2 report validation failed to account for fixed/stale baseline changes, and accepted inconsistent change metadata. | Validate change identities/states and include fixed/stale records in the summary. |
| HSP-07 | A Git lock's release disagreed with the vendored manifest but validation passed. | Bind nonempty release metadata to the manifest; preserve legacy Git locks without optional release metadata. |
| HSP-08 | An OCI lock's canonical archive digest disagreed with vendored content but validation passed. | Recompute the canonical bounded archive offline and require the recorded digest. |
| HSP-09 | A digest-pinned OCI coordinate disagreed with the lock's manifest digest but validation passed. | Bind the configured immutable coordinate to its recorded manifest digest. |
| HSP-10 | Injected vendored `.git` content was omitted from integrity checks. | Strict vendor digests reject root/nested Git metadata; source checkout operations still exclude top-level Git directories and linked-worktree indirection files. |
| HSP-11 | Published/pulled archives accepted Git metadata and unsafe portable filenames, including streams, device names and trailing-dot aliases. | Validate UTF-8 and portable path components consistently in archive production, extraction and vendor checks. |
| HSP-12 | File ancestors and case/Unicode aliases could cause partial extraction before failure. | Preflight the complete path set before any extracted write; use a component trie with 4096-byte and 64-component limits. |
| HSP-13 | Formatting a shared list of 90,000 empty strings charged roughly 303 cost units. | Charge at least one traversal unit for each string, including empty values, before formatting. |
| HSP-14 | Generic XML parsing silently discarded repeated and namespace-colliding attribute values. | Reject repeated local attribute names before projecting XML into its local-name representation. |
| HSP-15 | Invalid UTF-8 JSON was silently repaired to U+FFFD and could produce a passing decision. | Reject invalid UTF-8 at the shared strict JSON boundary; preserve valid replacement characters and ordinary Unicode. |
| HSP-16 | JSON underflow compared equal to zero in CEL, and nested unsupported numbers could be swallowed during equality. | Reject residual lexical numbers outside CEL's supported numeric range before evaluation; keep exact numeric constraints in `structured.fields`. |
| HSP-17 | NuGet source analysis accepted repeated/colliding attributes, missing/multiple roots and a nested section that hid a forbidden source. | Share strict attribute validation and track document/root/section depth without changing the streaming parser. |
| HSP-18 | `check`, `inventory` and report migration could overwrite configuration, locks, ignore policy or Git metadata. Missing policy parents and Unicode aliases were also writable. | Preflight shared policy inputs, pack roots, ancestors and physical/portable aliases. Preserve ordinary in-source reports, atomic final-symlink replacement and in-place report migration. |

Cross-review also rejected an initial quadratic archive-prefix implementation
before publication and retained a bounded allocation regression. It corrected
an initial report-threshold equality check to preserve legitimate stricter
thresholds. These are corrections to the proposed fixes, not additional
failures attributed to the shipped baseline.

## Consumer and qualification evidence

Qualification receipts are under the operator's local Codex artifact directory
`hoolicy-smoke-20261013/second-pass`. The frozen implementation list is
`implementation-hashes-start.json`; `qualification-summary.json` records the
commands, results and confirmation that implementation bytes did not change.
The final tested source commit is bound in `qualified-source.json` after the
signed commit, and exact-head CI qualifies the complete submitted tree.

- Real public Git acquisition and offline consumers: 14 checks, including no
  network attempts during ordinary offline use, tampered vendor rejection,
  restoration, and stale lock/ref rejection.
- Documented public Go SDK example: eight checks covering actual dependency
  resolution, extension compilation, missing/present input and stock CLI
  rejection of the unregistered kind.
- Native report-output consumer: all 24 unsafe destination scenarios across
  check, inventory and migration reproduce against downloaded v0.6.0 and are
  rejected by the frozen repaired binary. Four ordinary-output/symlink controls
  pass in both binaries: 28/28 expected results for each.
- Native document/CEL/NuGet consumer: 18/18 expected results against both the
  downloaded baseline and repaired binary. The repaired results include six
  passing, two blocking and ten operational-error controls.
- Local transport pack probes bind lock/release/archive metadata and path
  safety without asserting live registry trust from fake transports.

The final whole-tree qualification passed 72/72 gates. All 94 frozen Go/module/
Dockerfile inputs still match their start hashes. Independent receipt parsing
confirmed the following counts:

| Gate | Result |
| --- | --- |
| Full ordinary suite | 318 top-level tests and 431 subtests; 21 tested packages |
| Full race suite | Same 318 tests and 431 subtests; no race reports |
| Pack fixtures | 305/305 across all 15 packs |
| Pack verification, snapshots and lint | 45/45 commands |
| Native general consumer | 53/53 checks |
| CLI/service subprocess harness | 167/167 checks |
| Evidence ancestor controls | 4/4 checks |
| Checked-in policy examples and custom extension | All four examples and extension passed |
| Platform builds | Darwin arm64/amd64, Linux arm64/amd64 and Windows amd64 |
| Bounded strict JSON fuzzing | 57,629 executions; passed |
| Bounded document fuzzing | 2,996 executions; passed |

Neither full suite contains failed or skipped tests. Each has two package-level
skip records for packages without tests. Module tidiness, formatting, vet,
stable contracts, engine benchmarks and repository dogfood also passed.
Commands use Go 1.26.6 and serialize Go work with `GOMAXPROCS=2`, `-p=1` and
`-parallel=1`. Production time/cost limits, strict input consistency and test
timing assertions remain unchanged. Versioned `schemas/v1` files and valid SDK
digest golden values are unchanged. The repaired native pack consumer rejects
all four lock/vendor cases and all six hostile path cases; canonical hostile
archives produced by v0.6.0 install no files, with before/after listings and file
hashes, inodes, sizes and modification times unchanged.

## Practical limits

The first public SDK harness compiled its executable inside the evaluated
project, correctly triggering the 16 MiB document budget. The corrected
harness builds the executable outside the project. This was a harness mistake,
not a product failure. Failed receipts are retained.

Local pack transport fixtures prove application behavior, not real registry
signing or availability. Release qualification separately verifies real public
signatures and attestations. Linux amd64 runtime tests use Docker emulation on
an arm64 host; Windows and Darwin amd64 local gates are compile checks. Output
preflight does not lock the filesystem against unrelated concurrent writers.
CEL's numeric restrictions are documented rather than silently rounding exact
numbers into passing decisions.
