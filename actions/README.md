# Hoolicy actions

Use immutable action revisions in consuming repositories.

```yaml
- uses: openhoo/hoolicy/actions/check@<full-commit-sha>
  with:
    version: 0.3.0
```

`actions/setup` downloads the release archive and `SHA256SUMS`, verifies the
selected archive, checks the installed binary version, and adds it to `PATH`.
`actions/check` then runs `hoolicy doctor` and `hoolicy check`; pull requests
automatically use their base SHA and title unless explicit inputs override them.
Repository self-tests may set `executable` to a freshly built local binary;
normal consumers should omit it so the verified release installer runs.
