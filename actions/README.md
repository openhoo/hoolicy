# Hoolicy actions

Use immutable action revisions in consuming repositories.

```yaml
- uses: openhoo/hoolicy/actions/check@<full-commit-sha>
  with:
    version: 0.3.1
```

`actions/setup` installs a pinned Cosign verifier, downloads the release archive,
`SHA256SUMS`, and the matching `.sigstore.json` bundle for both the archive and
the checksum file. It verifies both blobs with certificate identity
`https://github.com/openhoo/hoolicy/.github/workflows/release.yml@refs/heads/main`
and OIDC issuer `https://token.actions.githubusercontent.com`, then checks the
archive checksum, installed binary version, and `PATH` setup. `actions/check`
then runs `hoolicy doctor` and `hoolicy check`; pull requests automatically use
their base SHA and title unless explicit inputs override them.
Repository self-tests may set `executable` to a freshly built local binary;
normal consumers should omit it so the verified release installer runs.
For GitHub code scanning, request `security-events: write`, select SARIF, and upload the generated file with the pinned CodeQL uploader:

```yaml
permissions:
  contents: read
  security-events: write

steps:
  - uses: openhoo/hoolicy/actions/check@<full-commit-sha>
    with:
      format: sarif
      output: hoolicy.sarif
  - if: always()
    uses: github/codeql-action/upload-sarif@cdf488f595d80d6e07e03d4674febd5ab45fa938 # v4
    with:
      sarif_file: hoolicy.sarif
```

The check action still returns `1` for policy findings and `2` for configuration, evaluation, or report-output failures; `if: always()` ensures findings are uploaded before the job reports the check status.
