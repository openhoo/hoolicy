# Workspaces and resource limits

Monorepo scopes are explicit. No child configuration or directory inheritance is read.

```yaml
workspaces:
  - name: api
    paths: [services/api/**]
    owner: '@api-team'
    packs: [service-policy]
    parameters: {environment: production}
    dependsOn: [shared]
  - name: shared
    paths: [shared/**]
    owner: '@platform-team'
```

Local root rules always evaluate the complete repository. Pack rules evaluate only workspaces selecting that pack, plus transitive `dependsOn` workspace inputs. Validation rejects actual overlapping or unowned repository files, cycles, unknown pack selection, and conflicting dependency parameters. Findings carry stable workspace and owner routing fields; notification delivery stays outside Hoolicy.

Structured documents use a bounded, content-digest cache. Matched rule inputs use a separate bounded cache keyed by repository content and active policy digest. Changed content, dependency scope, parameters, or policy therefore cannot reuse stale inputs. Incremental and clean evaluation still execute the same rules and produce identical findings and fingerprints.

Reports include per-rule duration, input count, input-cache hits, parse-cache hits, CEL cost, findings, and total file/byte/time metrics. Timings and cache counts are observational and excluded from policy decisions. Hard budgets cover repository files, individual document bytes, findings, per-rule time, and total time.

`hoolicy inventory` emits scopes, owners, paths, packs, parameters, active rule versions and digests, controls, waivers, and policy digest. `hoolicy serve` exposes only `GET /health`, `GET /v1/check`, and `GET /v1/inventory` on an explicit numeric loopback address such as `127.0.0.1:8941` or `[::1]:8941`; hostnames are rejected. It has no mutation endpoint and is optional; normal commands use the same engine without it.
