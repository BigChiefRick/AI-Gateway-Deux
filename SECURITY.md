# Security policy

## Reporting

Report suspected vulnerabilities, credential exposure, policy bypass, or data
leakage through the deployment owner's private security-reporting process. Do not open a public
issue or include sensitive evidence in a pull request.

## Credential handling

- Store AI Gateway credentials only in the approved Bitwarden Secrets
  Manager project.
- Use separate least-privilege machine accounts for deployment, gateway runtime,
  Mem0 runtime, and CI/CD when their access differs.
- Keep values out of source, Markdown, issue bodies, pull-request text, Actions
  logs, container images, shell history, and durable AI memory.
- Documentation may contain safe secret names, IDs, environment-variable names,
  paths, fingerprints, hashes, owners, and rotation metadataâ€”but never values.
- Revoke and rotate before investigating or remediating a suspected exposure.

## Target design boundaries

These are acceptance requirements for the target architecture, not a claim that the reference implementation currently enforces every boundary. See [implementation status](docs/implementation-status.md).

### Required boundaries

- Archestra is mandatory for managed portal, agent, IDE/CLI, model, and MCP
  traffic.
- Microsoft Entra supplies identity and lifecycle control.
- Deterministic DLP and MCP policies are authoritative; model classification is
  advisory.
- Provider-native enterprise controls and Microsoft Purview/Defender govern
  native provider and bypass paths.
- Self-hosted Mem0 accepts only sanitized, provenance-bearing organizational
  knowledge from the managed policy path.
