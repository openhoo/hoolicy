# Performance and footprint

Hoolicy ships one statically linked Go binary in a `scratch` image. The image has no shell, package manager, certificates, duplicated assets, or bundled application data. Runtime image size is therefore binary size plus a temporary-directory marker and OCI metadata.

## Measured results

Benchmark baseline is the implementation published in `v0.1.2`. Measurements used Linux amd64, an Intel Core i9-14900K, and the pinned Go 1.26.6 Alpine builder. Values are medians of five runs unless noted otherwise. Artifact measurements compare the published `v0.1.1` and `v0.1.2` releases.

| Workload | Baseline | Optimized | Change |
| --- | ---: | ---: | ---: |
| Match four include and two exclude globs across 20,000 files | 706.67 ms | 30.94 ms | 22.8x faster |
| Glob workload allocated bytes, one iteration | 458.57 MB | 1.05 MB | 99.8% lower |
| CEL validation and evaluation | 345.88 us | 92.00 us | 3.8x faster |
| CEL allocated bytes | 105.49 KB | 41.35 KB | 60.8% lower |
| Full check: 500 JSON files, three representative rules | 32.05 ms | 14.01 ms | 2.3x faster |
| Full-check allocated bytes | 16.94 MB | 3.90 MB | 77.0% lower |
| Built-in pack tests: 10 fixtures | 344.21 ms | 78.71 ms | 4.4x faster |

Footprint stayed essentially flat while adding bounded caches and benchmarks:

| Artifact | Baseline | Optimized | Change |
| --- | ---: | ---: | ---: |
| Stripped Linux amd64 binary | 11,980,962 B | 11,976,830 B | 4,132 B smaller |
| Runtime image | 11,987,596 B | 11,984,502 B | 3,094 B smaller |
| Compressed OCI layer | 4,362,368 B | 4,359,770 B | 2,598 B smaller |

The runtime image remains one layer. Local comparison on 2026-08-27 measured HooCloak at 11,912,505 bytes and Hoomail at 14,278,924 bytes, putting Hoolicy within 72 KB of HooCloak and about 2.3 MB below Hoomail.

## What changed

- Include and exclude globs compile once per repository match instead of once per pattern, per file.
- A bounded process-local input cache binds matched paths to repository content plus policy digest; parsed-document caches remain content-addressed. Cache hits are observational report metrics and never alter findings.
- Match result storage allocates once at repository scale.
- Repository reads reuse the safe snapshot already loaded during discovery.
- Git branch, revision, and dirty state come from one porcelain-v2 status call. A check now uses three Git processes including file discovery, down from five.
- The registered CEL rule kind shares one environment and a bounded 128-entry compiled-program cache. Validation and evaluation no longer compile the same expression twice.
- Pack fixtures inject deterministic Git context instead of spawning five Git processes per case. This also keeps `hoolicy test` functional in the minimal image.
- Release builds omit development-only module metadata fallback, empty the Go build ID, disable VCS stamping, strip debug data, and retain normal compiler inlining.
- Docker builds use a digest-pinned Go builder, persistent module/build caches, and narrow source copies. Runtime remains `scratch` and non-root.

## Reproduce

```sh
go test ./internal/repository -run '^$' -bench BenchmarkRepositoryMatch -benchmem -count=5
go test ./internal/rules -run '^$' -bench BenchmarkCELValidateAndEvaluate -benchmem -count=5
go test ./internal/engine -run '^$' -bench 'BenchmarkEngine(SmallRepository|Check|LargeMonorepo|AdversarialLimit)$' -benchmem -count=5
podman build -t hoolicy:benchmark .
podman image inspect hoolicy:benchmark --format '{{.Size}}'
```

Compiler experiments were measured, not adopted blindly. Disabling inlining reduced the binary by 10.8% but slowed the full-check median by 11.2%. A representative PGO profile added 110,592 bytes and produced no repeatable median improvement. `GOAMD64=v3` saved only 12,324 bytes while dropping older amd64 compatibility. Default inlining, portable amd64, and no PGO gave the best balanced result.
