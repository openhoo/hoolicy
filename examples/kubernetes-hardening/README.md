# Kubernetes hardening example

With a Hoolicy build that includes structured.cel pack parameters and the CEL
lists extension, run from this directory:

```sh
hoolicy validate
hoolicy check
```

The provided `deploy/web.yaml` Deployment and CronJob pass every rule. To see
precise per-container findings, set `privileged: true` or remove
`allowPrivilegeEscalation: false` (blocking errors, exit 1), or remove
`readOnlyRootFilesystem` or a probe (warnings, exit 0 at `failOn: error`).
Adding `hostPath: {path: /var/log}` to a volume fails until `/var/log` is in
`host_path_allowed_paths`. Malformed YAML returns exit 2.

`policy/kubernetes-hardening/` is an exact copy of `packs/kubernetes-hardening/pack.yaml`,
vendored the way a consuming repository would keep it. The pack inspects
literal manifests only. Render Helm charts or Kustomize
overlays first and point `manifest_globs` at the rendered output.
