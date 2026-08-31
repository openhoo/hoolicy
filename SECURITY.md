# Security policy

## Supported versions

Security fixes target the latest `v0.3.x` release until a newer minor line is published.

## Reporting a vulnerability

Use GitHub private vulnerability reporting or open a private GitHub Security Advisory for `openhoo/hoolicy`. Do not publish exploit details in an issue.

Include affected version, operating system, minimal reproduction, impact, and any suggested mitigation. Expect acknowledgement within five business days. Release timing depends on severity and fix complexity.

Never include production credentials, private repository content, or personal data in a report.

## Security design

Hoolicy treats configuration, repositories, and policy packs as untrusted data. Runtime code loading and policy-triggered network or shell execution are out of scope by design. See [docs/architecture.md](docs/architecture.md) for trust boundaries and known behavior.
