# CI workflow security pack

Maintained structured YAML rules for GitHub Actions and GitLab CI. Reusable GitHub jobs defer timeout control to the called workflow; GitLab jobs may inherit explicit `default.timeout`. `pull_request_target` is reported when privileged execution checks out fork code or interpolates untrusted event data, not merely because the event exists. The pack does not execute workflow code and does not claim that a safe-looking workflow is a secure build system.

GitHub trigger strings, lists, and maps are inspected. Context references are checked throughout `${{ ... }}` expressions, including function arguments, fallbacks, and dot or quoted bracket access. Literal text inside an expression is excluded. Put untrusted event values in step environment variables and use quoted shell variables instead of interpolating those values directly into `run` scripts.
