# Architecture and threat model

Hoolicy separates policy data from executable behavior.

```text
hoolicy.yaml + vendored packs + waiver file
                    |
          strict parse and validation
                    |
 tracked/untracked non-ignored repository snapshot + Git context
                    |
        registered rule kinds or bounded CEL
                    |
        findings, safe edits, machine reports
```

## Trust boundaries

Project configuration and packs are untrusted data. Core rule kinds are compiled into the Hoolicy binary. A policy cannot load a shared library, invoke a shell, perform HTTP requests, or register a runtime plugin. CEL receives only normalized repository documents, file metadata, selected Git context, project parameters, and current time.

Remote packs are the only command path that uses the network. `hoolicy pack update` fetches a requested Git ref into temporary storage, rejects symlinks and non-regular files, vendors the pack beneath `.hoolicy/vendor`, and records Git commit plus deterministic SHA-256 tree digest in `hoolicy.lock`. `validate` and `check` only read that vendored copy and verify its digest.

Repository reads and fixes reject absolute paths, traversal, symlinks, and non-regular files. Git-ignored content and `.hoolicy/vendor` are excluded from normal repository matching. Direct rule reads remain within the repository boundary.

The system `git` executable is the fast path for file discovery, status, and commit metadata. Minimal images use a read-only built-in Git fallback for repository-local tracked, untracked, ignore, branch, commit, linked-worktree, and dirty-state inputs. If a bind-mounted Git index is unreadable, the fallback derives tracked paths from `HEAD`, adds non-ignored worktree files, and marks the repository dirty conservatively. If Git metadata exists but neither path can interpret it safely, evaluation fails closed instead of walking ignored content or silently skipping Git rules.

## Evaluation model

1. Locate one `hoolicy.yaml`, stopping at the Git root.
2. Strictly decode configuration and all referenced manifests.
3. Resolve local packs or digest-verified vendored packs.
4. Validate every rule kind before reading policy targets.
5. Build a deterministic repository snapshot.
6. Evaluate rules in stable ID order.
7. Apply valid waivers; stale waivers become blocking lifecycle findings.
8. Sort findings and emit the selected report format.

Findings use stable SHA-256 fingerprints over rule ID, normalized path, location, and semantic key. Report `configDigest` covers configuration, lock, waivers, and instantiated active rules without depending on checkout location.

## Failure model

Policy violations return exit code `1`. Invalid configuration, pack tampering, parser errors, unsafe paths, evaluation failures, and report errors return `2`. Hoolicy does not turn parser failure into a clean result.

## Safe fixes

Rule kinds may propose byte-range edits with expected file SHA-256. `hoolicy fix` builds a complete plan only when targets are clean and edits do not overlap. Preview is default. `--apply` rechecks every original byte sequence, stages replacements in the target filesystem, atomically renames files, and rolls back already-applied files after a later failure.

## Compile-time extensions

Custom organizations can build a binary containing additional `sdk.RuleKind` implementations. The public `github.com/openhoo/hoolicy` package registers core kinds and starts the normal CLI. No extension is accepted from configuration at runtime. See [sdk.md](sdk.md).
