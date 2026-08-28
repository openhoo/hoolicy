# CI workflow security pack

Maintained structured YAML rules for GitHub Actions and GitLab CI. Reusable GitHub jobs defer timeout control to the called workflow; GitLab jobs may inherit explicit `default.timeout`. `pull_request_target` is reported when privileged execution checks out fork code or interpolates untrusted event data, not merely because the event exists. The pack does not execute workflow code and does not claim that a safe-looking workflow is a secure build system.
