# Safety and limitations

## Non-negotiable runtime limit

This release only simulates. It cannot contact a target, scan a network, issue DNS/HTTP/TLS requests, launch external programs, run shell commands, exploit a vulnerability, guess credentials, or accept a custom tool backend. The built-in provider returns fixed synthetic records from Python data. This is enforced by the gateway and fixed registry; YAML tool files cannot enable another backend or pass command parameters.

The word “target” in this prototype is a label used for scope checks and report display. It is never resolved or contacted. The optional MCP interface is stdio-only and exports only a list operation plus a fixture simulation operation.

## Scope and approvals

Scopes are Ed25519-signed, time-bounded, schema-validated, and limited to `mock_only`. The gateway denies categories outside the manifest and role policy; exclusions override allowed domains, IPs, CIDRs, and URL prefixes. Invalid signatures, stale scope, malformed targets, unknown tools, unknown principals, extra arguments, and audit write failures fail closed.

The CLI's approval prompt gates only one additional offline fixture. Approval is not authorization to perform real security testing. Tokens are random, hashed at rest, single-use, expire within 15 minutes, and are bound to one engagement and reviewer.

Possessing a signing key does not prove legal permission to test any system. The default uses the documentation-only IP range `192.0.2.0/24`; users selecting another label must independently obtain written authorization. Because the current release does not contact targets, a scope should not be interpreted as evidence of a test.

## Known limitations

- The audit chain is local and tamper-evident, not tamper-proof or externally anchored. SQLite is not encrypted at rest by this project.
- The CLI and stdio MCP process rely on the local OS account. There is no remote identity provider, multi-user service, TCP listener, or network authentication.
- The fixture records are examples, not evidence, vulnerability assessments, remediation advice, or current CVE intelligence.
- Docker Compose runtime settings disable network access and drop privileges, but Docker was unavailable in the build environment and the image has not been executed here. The test suite does not depend on Docker.
- Dependencies and the host remain part of the trusted computing base.

A live-testing extension is outside this version's scope and requires explicit user direction, a separate threat model, and a new security review. Do not describe this prototype as an autonomous scanner or exploit-validation system.
