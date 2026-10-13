# GitHub Actions hardening example

With a Hoolicy build that includes the bounded CEL lists, strings, and
two-variable comprehension extensions, run from this directory:

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

Privileged checkout recognizes dot access and constant single-quoted bracket
access, including `${{ github['event']['pull_request']['head']['sha'] }}`.
Text inside expression string literals is treated as literal text. A checkout
guard must start with the positive same-repository comparison or
`workflow_run.event == 'push'`; surrounding parentheses and expression braces
are accepted. Trailing `&&` conditions pass when they contain no `||`.
The explicit `(workflow_run && success && push) || workflow_dispatch` condition
in the pack fixtures also passes. Other conditional forms need a reviewed
waiver. Guard text in a quoted string, negated comparisons, and arbitrary
`||` alternatives do not exempt a checkout.
