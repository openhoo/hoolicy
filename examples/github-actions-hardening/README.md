# GitHub Actions hardening example

With Hoolicy 0.5 or newer, run from this directory:

```sh
hoolicy validate
hoolicy check
```

`hoolicy.yaml` contains the rules of the experimental
`github-actions-hardening` pack with parameters expanded and pinning extended
to workflow files. The provided workflow and composite action pass.

To see findings and exit 1:

- change the checkout reference to `actions/checkout@v4`;
- remove `persist-credentials: false` (warning);
- remove the top-level `permissions` block;
- interpolate `${{ github.event.pull_request.title }}` directly into the
  composite action `run` script;
- add a `pull_request_target` trigger and check out
  `${{ github.event.pull_request.head.sha }}`.

Malformed YAML returns exit 2. No package manager, network acquisition, or
external service is needed. In a real repository, vendor the pack with
`hoolicy pack add` and set its parameters instead of copying rules.
