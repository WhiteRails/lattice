# Security policy

## Support boundary

Lattice 0.1.x is a pre-production candidate. The release target is Linux LNP/1.
There is no supported public production release at present. The archived
HTTP/WebSocket overlay and unsigned macOS/Windows adapters are not supported
deployment targets. New releases must pass the gates in `RUNBOOK.md`.

## Reporting vulnerabilities

Use the repository's **Security → Report a vulnerability** private reporting
channel when enabled: https://github.com/WhiteRails/lattice/security/advisories/new.
If private reporting is unavailable, open a public issue requesting a private
contact without including vulnerability details, exploit code, or secrets.
Do not publish private keys, session tokens, profiles with enrollment tokens,
or captured user payloads in issues or logs.

Include the affected commit/release, platform, minimal reproduction, expected
and actual behavior, and whether the issue crosses an authorization boundary.
Maintainers must enable private reporting and assign a response owner before
public production release. No response-time SLA is currently promised.

## Release security gates

- No known dependency vulnerability in shipped lockfiles; documented disposition
  of unmaintained or yanked dependencies.
- Regression tests for every verified security fix and privileged Linux E2E.
- Independent security review of the exact candidate before public enablement.
- Artifact provenance verification, recovery/rotation exercise, and a tested
  rollback that does not reopen unauthorized traffic.

Passing these gates does not certify AI alignment or protection against all
possible actions within an otherwise authorized service.
